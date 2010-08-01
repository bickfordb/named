{-# LANGUAGE DeriveDataTypeable #-}
module NameDaemon (nameDaemon, runServer, Question(..), Message(..), Answer(..)) where

import Control.Concurrent
import Control.Concurrent.MVar
import Control.Monad
import Data.Bits
import Data.Char
import Data.Serialize
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Word
import Network.Socket hiding (recv, recvFrom, send, sendTo)
import Network.Socket.ByteString 
import System.Console.CmdArgs
import qualified Data.ByteString as S

data NameDaemonOptions = NameDaemonOptions {optHost :: String, optPort :: String}
    deriving (Data, Show, Typeable, Eq)

setupSockets :: String -> String -> IO (Socket, Socket)
setupSockets name port = do 
    let hints = Just $ defaultHints { addrFlags=[AI_PASSIVE] }
    addrInfos <- getAddrInfo hints (Just name) (Just port)
    let serverAddr = head addrInfos
    tcpSocket <- socket (addrFamily serverAddr) Stream defaultProtocol
    bindSocket tcpSocket (addrAddress serverAddr)
    udpSocket <- socket (addrFamily serverAddr) Datagram defaultProtocol
    bindSocket udpSocket (addrAddress serverAddr)
    listen tcpSocket 10
    return (tcpSocket, udpSocket)

maxUDPPacketSize = 10000
runUDP socket queryHandler = forever $ do
    (buf, remoteAddr) <- recvFrom socket maxUDPPacketSize 
    forkIO $ handleUDPRequest socket remoteAddr buf queryHandler
    return ()

runTCP socket queryHandler = forever $ do
    (connSocket, remoteAddr) <- accept socket 
    forkIO $ handleTCPConn connSocket remoteAddr queryHandler

handleTCPConn socket addr queryHandler = do 
    readFrameLength
    sClose socket
    where 
        readFrameLength = do
            buf <- recv socket 2 
            case runGet getWord16be buf of 
                Left err -> return ()
                Right num -> do
                    let num' = fromIntegral num
                    if num' == 0 
                        then return ()
                        else readFrame num'
        readFrame size = do
            frameBytes <- recv socket size
            if S.length frameBytes /= size
                then return ()
                else
                    case decode frameBytes of
                        Left err -> do
                            print $ "decode error: " ++ show err
                        Right msg -> do
                            response <- queryHandler addr msg
                            sendResponse response
        sendResponse msg = do
                sendAll socket frameLengthBuf
                sendAll socket frameBuf
            where
                frameBuf = encode msg
                frameLengthBuf = runPut $ putWord16be $ fromIntegral $ S.length frameBuf

data Question = Question { 
    qName :: S.ByteString,
    qType :: Int,
    qClass :: Int}
    deriving (Show, Ord, Eq)

data Answer = Answer {
    ansName :: S.ByteString,
    ansClass :: Int,
    ansType :: Int,
    ansTTL :: Int,
    ansData :: S.ByteString}
    deriving (Show, Ord, Eq)

data Message = Message {
        msgID :: Int,
        msgOpCode :: Int,
        msgIsQueryResponse :: Bool,
        msgIsRecursionDesired :: Bool,
        msgIsTruncated :: Bool,
        msgIsRecursionAvailable :: Bool,
        msgIsAuthoritativeAnswer :: Bool,
        msgResponseCode :: Int,
        msgQuestions :: [Question],
        msgAnswers :: [Answer],
        msgNameservers :: [Answer],
        msgAdditional :: [Answer]
    } deriving (Show, Ord, Eq)

emptyMessage = Message {
    msgID=0,
    msgOpCode=0,
    msgIsQueryResponse=False,
    msgIsRecursionAvailable=False,
    msgIsRecursionDesired=False,
    msgIsTruncated=False,
    msgIsAuthoritativeAnswer=False,
    msgResponseCode=0,
    msgQuestions=[],
    msgAnswers=[],
    msgNameservers=[],
    msgAdditional=[]}

-- Message Serialization
instance Serialize Message where
    put msg = do
            putWord16be $ fromIntegral $ msgID msg
            putWord8 opts1
            putWord8 opts2
            putWord16be $ fromIntegral $ length $ msgQuestions msg
            putWord16be $ fromIntegral $ length $ msgAnswers msg
            putWord16be $ fromIntegral $ length $ msgNameservers msg
            putWord16be $ fromIntegral $ length $ msgAdditional msg
            mapM_ put $ msgQuestions msg
            mapM_ put $ msgAnswers msg
            mapM_ put $ msgNameservers msg
            mapM_ put $ msgAdditional msg
        where 
            opts1 = fromIntegral $ qrbits .|. opcodebits .|. aabits .|. tcbits .|. rdbits
            opts2 = fromIntegral $ rabits .|. rcodebits
            qrbits = if msgIsQueryResponse msg then bit 7 else 0
            opcodebits = shiftL ((msgOpCode msg) .&. 0x15) 3
            aabits = if msgIsAuthoritativeAnswer msg then bit 2 else 0
            tcbits = if msgIsTruncated msg then bit 1 else 0
            rdbits = if msgIsRecursionDesired msg then bit 0 else 0
            rabits = if msgIsRecursionAvailable msg then bit 7 else 0
            rcodebits = 0x15 .&. (msgResponseCode msg)
    get = do
        -- Header
        messageID <- liftM fromIntegral getWord16be
        opts1 <- liftM fromIntegral getWord8
        opts2 <- liftM fromIntegral getWord8
        let isQueryResponse = testBit opts1 7
            opCode = (shiftR opts1 3) .&. 0x15 
            isAuthoritativeAnswer = testBit opts1 2
            isTruncated = testBit opts1 1
            isRecursionDesired = testBit opts1 0
            isRecursionAvailable = testBit opts2 7
            responseCode = opts2 .&. 0x15
        questionCount <- liftM fromIntegral getWord16be
        answerCount <- liftM fromIntegral getWord16be
        nsCount <- liftM fromIntegral getWord16be
        additionalCount <- liftM fromIntegral getWord16be

        -- Read questions, answers, nameservers, additional
        questions <- replicateM questionCount get
        answers <- replicateM answerCount get
        nameservers <- replicateM nsCount get
        additionals <- replicateM additionalCount get
        return $ emptyMessage {
            msgID=messageID,
            msgIsQueryResponse=isQueryResponse,
            msgOpCode=opCode,
            msgIsTruncated=isTruncated,
            msgIsRecursionDesired=isRecursionDesired,
            msgIsRecursionAvailable=isRecursionAvailable,
            msgResponseCode=responseCode,
            msgQuestions=questions,
            msgAnswers=answers,
            msgNameservers=nameservers,
            msgAdditional=additionals}

instance Serialize Question where
    put q = do
        putName $ qName q
        putWord16be $ fromIntegral $ qType q
        putWord16be $ fromIntegral $ qClass q
    get = do
        name <- nameParser
        qtype <- liftM fromIntegral getWord16be
        qclass <- liftM fromIntegral getWord16be
        return $ Question {qName=name, qType=qtype, qClass=qclass}

putName name = do 
    mapM_ putChunk chunks
    putWord8 $ fromIntegral 0
    where 
        chunks = S.split (fromIntegral $ ord '.') name
        putChunk chunk = do
            putWord8 $ fromIntegral $ S.length chunk
            putByteString chunk

instance Serialize Answer where
    put ans = do
        putName $ ansName ans
        putWord16be $ fromIntegral $ ansType ans
        putWord16be $ fromIntegral $ ansClass ans
        putWord32be $ fromIntegral $ ansTTL ans
        putWord16be $ fromIntegral $ S.length $ ansData ans
        putByteString $ ansData ans

    get = do 
        ansName <- nameParser
        ansType <- liftM fromIntegral getWord16be
        ansClass <- liftM fromIntegral getWord16be
        ansTTL <- liftM fromIntegral getWord32be
        rdLength <- liftM fromIntegral getWord16be
        ansData <- getBytes rdLength
        return $ Answer {ansName=ansName, ansType=ansType, ansClass=ansClass, ansTTL=ansTTL, ansData=ansData}

handleUDPRequest socket remoteAddr buf queryHandler = do
    case decode buf of 
        Right msg -> do
            responseMessage <- queryHandler remoteAddr msg
            sendUDPResponse socket remoteAddr responseMessage
        Left err -> do
            print $ "failure: " ++ err

classInternet = 1

typeA = 1
typeNS = 2
typePTR = 12
typeCNAME = 5
typeMX = 15
typeTXT = 16

-- Generates TXT responses which reverse the query label
reverseResponse :: SockAddr -> Message -> IO Message
reverseResponse remoteAddr message = do 
        answers <- liftM concat $ mapM buildAnswers $ msgQuestions message
        return $ message {msgIsQueryResponse=True, msgAnswers=answers, msgIsTruncated=False, msgIsRecursionDesired=False, msgIsRecursionAvailable=False, msgIsAuthoritativeAnswer=True}
    where 
      buildAnswers question = do
            return $ [Answer {ansName=ansName, ansClass=ansClass, ansType=ansType, ansTTL=ansTTL, ansData=ansData}]
        where ansData = encodeCharacterString $ S.reverse $ qName question
              ansTTL = 86400
              ansName = qName question
              ansType = typeTXT   
              ansClass = classInternet

sendUDPResponse socket remoteAddr msg = do
    let buf = if S.length bufMsg <= 512 then bufMsg else bufTruncated
        bufMsg = encode msg
        bufTruncated = S.take 512 (encode (msg {msgIsTruncated=True, msgAnswers=[], msgAdditional=[], msgNameservers=[]}))
    ecode <- sendTo socket buf remoteAddr
    if ecode < 0 
        then print $ "error sending: " ++ (show ecode)
        else if ecode /= S.length buf 
                then print "cant send full length"
                else return () 

-- Split a bytestring into n-length chunks
splitManyAt n s
    | s == S.empty = []
    | length <= n  = [s]
    | otherwise    = l : (splitManyAt n r)
    where (l, r) = S.splitAt n s
          length = S.length s 

encodeCharacterString :: S.ByteString -> S.ByteString
encodeCharacterString s 
    | s == S.empty = encodeLength 0
    | otherwise    = S.concat $ addLengthPrefixes chunks
    where 
        addLengthPrefixes [] = [] 
        addLengthPrefixes (x : xs) = (encodeLength $ S.length x) : x : (addLengthPrefixes xs)
        chunks = splitManyAt maxLabelLength s

maxLabelLength = 63

encodeLength n = S.singleton $ fromIntegral n

dot = S.singleton $ fromIntegral $ ord '.'

nameParser = do
    parts <- nameParser'
    return $ S.intercalate dot parts
    where 
        nameParser' = do 
            size <- liftM fromIntegral getWord8
            if size > 0
                then do
                    bytes <- getBytes size
                    rest <- nameParser'
                    return $ bytes : rest
                else return []

runServer host port handler = do
   (tcpSocket, udpSocket) <- setupSockets host port
   forkIO $ runTCP tcpSocket handler
   runUDP udpSocket handler
   return ()

nameDaemon = do 
   addr <- cmdArgs "named" [mode $ NameDaemonOptions {
    optHost=def &= explicit & flag "host",
    optPort="53" &= explicit & flag "port"}]
   runServer (optHost addr) (optPort addr) reverseResponse


main = nameDaemon
