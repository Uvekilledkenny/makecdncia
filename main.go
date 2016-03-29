package main

import (
    "errors"
    "strconv"
    "encoding/hex"
    "bytes"
    "encoding/binary"
    "io/ioutil"
    "strings"
    "os"
)

const (
    sigTypeRSA4096SHA1 = 10000
	sigTypeRSA2048SHA1 = 10001
	sigTypeECDSASHA1 = 10002
	sigTypeRSA4096SHA256 = 10003
	sigTypeRSA2048SHA256 = 10004
	sigTypeECDSASHA256 = 10005
) 

type tmd struct {
    TitleID []byte
    HeaderChunk []byte
    contentChunkRecs []contentChunkRec
    CertCP []byte
}

type contentChunkRec struct {
	ContentID [0x4]byte
	ContentIndex [0x2]byte
	ContentType [0x2]byte
	ContentSize [0x8]byte
	SHA256Hash [0x20]byte
}

type tk struct {
    TitleID []byte
    HeaderChunk []byte
    CertCA []byte
    CertXS []byte
}

type ciaHdr struct {
    HdrSize uint32
    Type uint16
    Ver uint16
    CertSize uint32
    TikSize uint32
    TmdSize uint32
    MetaSize uint32
    ContentSize uint64
    ContentIndex [8192]byte
}

func hexToInt(dat []byte, base int, size int) (i uint64, err error) {
    i, err = strconv.ParseUint(hex.EncodeToString(dat), base, size)
    if err != nil { return 0, err }
    return i, nil
}

func getSigSize(sigType uint64) (size int, err error) {
    switch sigType {
    case sigTypeRSA4096SHA1:
    case sigTypeRSA4096SHA256:
        size = 576
    case sigTypeRSA2048SHA1:
    case sigTypeRSA2048SHA256:
        size = 320
    case sigTypeECDSASHA1:
    case sigTypeECDSASHA256:    
        size = 128
    default: 
        err := errors.New("Bad Signature Type")
        return 0, err        
    }
    return size, nil
}

func getCOffsets(tmd []byte) (offsets []int, err error) {
    var cOffsets []int
    contentCount, err := hexToInt(tmd[0x1DE:0x1E0], 10, 4)
    if err != nil { return nil, err }
    
    for i := 0; i < int(contentCount); i++ {
        cOffsets = append(cOffsets, 0xB04 + 0x30 * i)
    }
    
    return cOffsets, nil
}

func processTMD(TMD []byte) (t tmd, err error) {
    sigType, err := hexToInt(TMD[0:4], 10, 32)
    if err != nil {return tmd{}, err}
    
    sigSize, err := getSigSize(sigType)
    if err != nil {return tmd{}, err}
    
    offsets, err := getCOffsets(TMD) 
    if err != nil {return tmd{}, err}
    
    for i := 0; i < len(offsets); i++ {
        var cnt contentChunkRec
        data := TMD[offsets[i]:offsets[i]+0x30]
        buf := bytes.NewReader(data)
        err := binary.Read(buf, binary.LittleEndian, &cnt)
        if err != nil { return tmd{}, err }
        t.contentChunkRecs = append(t.contentChunkRecs, cnt)
    }
    
    certOffset := offsets[len(offsets)-1]+ 0x30
    t.TitleID = TMD[sigSize+76:sigSize+84] 
    t.HeaderChunk = TMD[0:certOffset]
    t.CertCP = TMD[certOffset:certOffset+768]
    
    return t, nil 
}

func processTk(CETK []byte) (TK tk, err error) {
    sigType, err := hexToInt(CETK[0:4], 10, 32)
    if err != nil {return tk{}, err}
    
    sigSize, err := getSigSize(sigType)
    if err != nil {return tk{}, err}
    
    TK.CertXS = CETK[sigSize+528:sigSize+1296]
    TK.CertCA = CETK[sigSize+1296:sigSize+2320]    
    TK.HeaderChunk = CETK[0:sigSize+528]
    TK.TitleID = TK.HeaderChunk[sigSize+156:sigSize+164]
    
    return TK, nil 
}

func genCiaHDR(TMD tmd, CETK tk) (CiaHdr ciaHdr, err error) {
    CiaHdr.HdrSize = 0x2020
    CiaHdr.Type = 0x00
    CiaHdr.Ver = 0x00
    CiaHdr.CertSize = uint32(len(CETK.CertCA) + len(CETK.CertXS) + len(TMD.CertCP))
    CiaHdr.TikSize = uint32(len(CETK.HeaderChunk))
    CiaHdr.TmdSize = uint32(len(TMD.HeaderChunk))
    CiaHdr.MetaSize = 0x00
    
    var size uint64
    
    for i := 0; i < len(TMD.contentChunkRecs); i++ {
        parse, err := hexToInt(TMD.contentChunkRecs[i].ContentSize[:], 16, 64)
        if err != nil {return ciaHdr{}, err}
        size = size + parse
    }
    
    CiaHdr.ContentSize = size
    
    for i := 0; i < len(TMD.contentChunkRecs); i++ {
        index, err := hexToInt(TMD.contentChunkRecs[i].ContentIndex[:], 16, 16)
        if err != nil {return ciaHdr{}, err}
        CiaHdr.ContentIndex[index >> 3] |= 0x80 >> (index & 7)
    }
    
    return CiaHdr, nil
}

func getPadding(length int) (padding []byte) {    
    if length % 64 != 0 {
        size := 64 - length % 64 
        padding, _ := hex.DecodeString(strings.Repeat("00", size))
        return padding
    } 
    return nil
}

func toLE(dat []byte) (datLE []byte) {
    var bDat bytes.Buffer
    _ = binary.Write(&bDat, binary.LittleEndian, dat)
    datLE = bDat.Bytes()
    return datLE
}

func genCia(CETK tk, TMD tmd, cdnDir string, dir string, file string) (err error) {
    f, err := os.Create(dir + file + ".cia")
    if err != nil { return err }
    
    defer f.Close()
    
    ciahdr, err := genCiaHDR(TMD, CETK)
    if err != nil { return err }
    
    var bCia bytes.Buffer
    err = binary.Write(&bCia, binary.LittleEndian, ciahdr)
    
    f.Write(bCia.Bytes())
    f.Write(getPadding(len(bCia.Bytes())))
    
    f.Write(toLE(CETK.CertCA))
    f.Write(toLE(CETK.CertXS))
    f.Write(toLE(TMD.CertCP))
    f.Write(getPadding(len(CETK.CertCA) + len(CETK.CertXS) + len(TMD.CertCP)))
    
    f.Write(toLE(CETK.HeaderChunk))
    f.Write(getPadding(len(CETK.HeaderChunk)))
    
    f.Write(toLE(TMD.HeaderChunk))
    f.Write(getPadding(len(TMD.HeaderChunk)))
    
    for i := 0; i < len(TMD.contentChunkRecs); i++ {
        cnt, err := ioutil.ReadFile(cdnDir + "/" + hex.EncodeToString(TMD.contentChunkRecs[i].ContentID[:]))
        if err != nil {return err}
        f.Write(cnt)
    }
    
    if err != nil { return err }
    
    return nil
}

// BuildCia builds a .cia file from the CDN files
func BuildCia(CDNDir string, CiaDir string, CiaName string) (err error) {
    tmd, err := ioutil.ReadFile(CDNDir + "/TMD")
    if err != nil { return err }
        
    cetk, err := ioutil.ReadFile(CDNDir + "/CETK")
    if err != nil { return err }
    
    strcTmd, err := processTMD(tmd)
    if err != nil { return err } 
    
    strcCetk, err := processTk(cetk)
    if err != nil { return err } 

    err = genCia(strcCetk, strcTmd, CDNDir, CiaDir, CiaName)

    return nil
}

func main() {
    err := BuildCia(os.Args[1], "", os.Args[2])
    if err != nil {panic(err)}
}