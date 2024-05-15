{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
{  https://bitbucket.org/lminuti/delphi-openssl                                }
{  Copyright (c) 2024 Lsuper                                                   }
{  https://github.com/delphilite/DelphiOpenSSL                                 }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}

unit OpenSSL.Core;

interface

uses
  System.SysUtils, OpenSSL.Api_11;

const
  SSL_API_SUCCESS       = 1;

type
  EOpenSSL = class(Exception);

  EOpenSSLError = class(EOpenSSL)
  private
    FErrorCode: Integer;
  public
    constructor Create(AErrorCode: Integer; const AMessage: string);

    property  ErrorCode: Integer read FErrorCode;
  end;

  TOpenSSLBase = class(TObject)
  public
    constructor Create; virtual;
  end;

  function  Base64Encode(const AData: Pointer;
    const ASize: Integer): TBytes; overload;
  function  Base64Decode(const AData: Pointer;
    const ASize: Integer): TBytes; overload;
  function  Base64Encode(const AData: TBytes): TBytes; overload;
  function  Base64Decode(const AData: TBytes): TBytes; overload;

  function  BytesToHex(const AData: TBytes; ALowerCase: Boolean = True): string;
  function  HexToBytes(const AData: Pointer; ASize: Integer): TBytes; overload;
  function  HexToBytes(const AData: string): TBytes; overload;

  function  BIO_flush(b: PBIO): Integer;
  function  BIO_get_mem_data(b: PBIO; pp: Pointer): Integer;
  function  BIO_get_mem_ptr(b: PBIO; pp: Pointer): Integer;
  function  BIO_to_string(b: PBIO; Encoding: TEncoding): string; overload;
  function  BIO_to_string(b: PBIO): string; overload;

  function  EVP_GetSalt: TBytes;
  procedure EVP_GetKeyIV(const APassword: TBytes; ACipher: PEVP_CIPHER;
    const ASalt: TBytes; out Key, IV: TBytes); overload;
  { Password will be encoded in UTF-8 if you want another encodig use the TBytes version }
  procedure EVP_GetKeyIV(const APassword: string; ACipher: PEVP_CIPHER;
    const ASalt: TBytes; out Key, IV: TBytes); overload;

  function  LastOpenSSLError: string;
  procedure RaiseOpenSSLError(const AMessage: string = '');

implementation

function Base64Encode(const AData: Pointer; const ASize: Integer): TBytes;
const
  BASE64_ENCODE: array[0..64] of Byte = (
    // A..Z
    $41, $42, $43, $44, $45, $46, $47, $48, $49, $4A, $4B, $4C, $4D,
    $4E, $4F, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A,
    // a..z
    $61, $62, $63, $64, $65, $66, $67, $68, $69, $6A, $6B, $6C, $6D,
    $6E, $6F, $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, $7A,
    // 0..9
    $30, $31, $32, $33, $34, $35, $36, $37, $38, $39,
    // +, /, =
    $2B, $2F, $3D
  );
var
  B: Byte;
  B64: array [0..3] of Byte;
  I, SrcIndex, DstIndex: Integer;
  Src: PByte;
begin
  if (AData = nil) or (ASize = 0) then
  begin
    Result := nil;
    Exit;
  end;

  SetLength(Result, ((ASize + 2) div 3) * 4);
  Src := AData;
  SrcIndex := 0;
  DstIndex := 0;

  while (SrcIndex < ASize) do
  begin
    B := Src[SrcIndex];
    Inc(SrcIndex);

    B64[0] := B shr 2;
    B64[1] := (B and $03) shl 4;

    if (SrcIndex < ASize) then
    begin
      B := Src[SrcIndex];
      Inc(SrcIndex);

      B64[1] := B64[1] + (B shr 4);
      B64[2] := (B and $0F) shl 2;

      if (SrcIndex < ASize) then
      begin
        B := Src[SrcIndex];
        Inc(SrcIndex);

        B64[2] := B64[2] + (B shr 6);
        B64[3] := B and $3F;
      end
      else
        B64[3] := $40;
    end
    else
    begin
      B64[2] := $40;
      B64[3] := $40;
    end;

    for I := 0 to 3 do
    begin
      Assert(B64[I] < Length(BASE64_ENCODE));
      Assert(DstIndex < Length(Result));
      Result[DstIndex] := BASE64_ENCODE[B64[I]];
      Inc(DstIndex);
    end;
  end;
  SetLength(Result, DstIndex);
end;

function Base64Encode(const AData: TBytes): TBytes;
begin
  if Assigned(AData) then
    Result := Base64Encode(@AData[0], Length(AData))
  else Result := nil;
end;

function Base64Decode(const AData: Pointer; const ASize: Integer): TBytes;
const
  BASE64_DECODE: array[0..255] of Byte = (
    $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $3E, $FF, $FF, $FF, $3F,
    $34, $35, $36, $37, $38, $39, $3A, $3B, $3C, $3D, $FF, $FF, $FE, $FF, $FF, $FF,
    $FF, $00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $0A, $0B, $0C, $0D, $0E,
    $0F, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $FF, $FF, $FF, $FF, $FF,
    $FF, $1A, $1B, $1C, $1D, $1E, $1F, $20, $21, $22, $23, $24, $25, $26, $27, $28,
    $29, $2A, $2B, $2C, $2D, $2E, $2F, $30, $31, $32, $33, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
  );
var
  B: Byte;
  C: Cardinal;
  Src: PByte;
  SrcIndex, DstIndex, Count: Integer;
begin
  if (AData = nil) or (ASize = 0) then
  begin
    Result := nil;
    Exit;
  end;

  SetLength(Result, (ASize div 4) * 3 + 4);
  Src := AData;
  SrcIndex := 0;
  DstIndex := 0;
  C := 0;
  Count := 4;

  while (SrcIndex < ASize) do
  begin
    B := BASE64_DECODE[Src[SrcIndex]];
    if (B = $FE) then
      Break
    else if (B <> $FF) then
    begin
      C := (C shl 6) or B;
      Dec(Count);
      if (Count = 0) then
      begin
        Result[DstIndex + 2] := Byte(C);
        Result[DstIndex + 1] := Byte(C shr 8);
        Result[DstIndex    ] := Byte(C shr 16);
        Inc(DstIndex, 3);
        C := 0;
        Count := 4;
      end;
    end;
    Inc(SrcIndex);
  end;

  if (Count = 1) then
  begin
    Result[DstIndex + 1] := Byte(C shr 2);
    Result[DstIndex    ] := Byte(C shr 10);
    Inc(DstIndex, 2);
  end
  else if (Count = 2) then
  begin
    Result[DstIndex] := Byte(C shr 4);
    Inc(DstIndex);
  end;

  SetLength(Result, DstIndex);
end;

function Base64Decode(const AData: TBytes): TBytes;
begin
  if Assigned(AData) then
    Result := Base64Decode(@AData[0], Length(AData))
  else Result := nil;
end;

function BufferToHex(const AData: Pointer; ASize: Integer; ALowerCase: Boolean): string;
type
  PHexCharMap = ^THexCharMap;
  THexCharMap = array[0..15] of Char;
const
  HEXCHAR_MAPL: THexCharMap = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  );
  HEXCHAR_MAPU: THexCharMap = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  );
var
  pData: PByte;
  pRet: PChar;
  pMap: PHexCharMap;
begin
  if ALowerCase then
    pMap := @HEXCHAR_MAPL
  else pMap := @HEXCHAR_MAPU;
  pData := AData;
  SetLength(Result, 2 * ASize);
  pRet := PChar(Result);
  while ASize > 0 do
  begin
    pRet^ := pMap[(pData^ and $F0) shr 4];
    Inc(pRet);
    pRet^ := pMap[pData^ and $0F];
    Inc(pRet);
    Dec(ASize);
    Inc(pData);
  end;
end;

function BytesToHex(const AData: TBytes; ALowerCase: Boolean): string;
begin
  Result := BufferToHex(Pointer(AData), Length(AData), ALowerCase);
end;

function HexToBytes(const AData: Pointer; ASize: Integer): TBytes;

  function HexByteToByte(B: Byte): Byte;
  begin
    case Chr(B) of
      '0'..'9':
        Result := Ord(B) - Ord('0');
      'a'..'f':
        Result := Ord(B) - Ord('a') + 10;
      'A'..'F':
        Result := Ord(B) - Ord('A') + 10;
    else
      begin
        raise EConvertError.CreateFmt('HexToBytes: %d', [Ord(B)]);
      end;
    end;
  end;

  function HexWordToByte(W: Word): Byte;
  var
    B0, B1: Byte;
    C: array[0..1] of Byte absolute W;
  begin
    B0 := HexByteToByte(C[0]);
    B1 := HexByteToByte(C[1]);
    Byte(Result) := B0 shl 4 + B1;
  end;
var
  nLen, nIndex: Integer;
  pData: PWord;
begin
  if ASize = 0 then
  begin
    Result := nil;
    Exit;
  end;
  if ASize and 1 <> 0 then
    raise EConvertError.Create('HexToBytes');
  nLen := ASize shr 1;
  SetLength(Result, nLen);
  nIndex := 0;
  pData := AData;
  while nIndex < nLen do
  begin
    Result[nIndex] := HexWordToByte(pData^);
    Inc(pData);
    Inc(nIndex);
  end;
end;

function HexToBytes(const AData: string): TBytes;
var
  B: TBytes;
begin
  B := TEncoding.Default.GetBytes(AData);
  Result := HexToBytes(Pointer(B), Length(B));
end;

function BIO_flush(b: PBIO): Integer;
begin
  Result := BIO_ctrl(b, BIO_CTRL_FLUSH, 0, nil);
end;

function BIO_get_mem_data(b: PBIO; pp: Pointer): Integer;
begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

function BIO_get_mem_ptr(b: PBIO; pp: Pointer): Integer;
begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

function BIO_to_string(b: PBIO; Encoding: TEncoding): string;
const
  BuffSize = 1024;
var
  Buffer: TBytes;
begin
  Result := '';
  SetLength(Buffer, BuffSize);
  while BIO_read(b, buffer, BuffSize) > 0 do
  begin
    Result := Result + Encoding.GetString(Buffer);
  end;
end;

function BIO_to_string(b: PBIO): string; overload;
begin
  Result := BIO_to_string(b, TEncoding.ANSI);
end;

function EVP_GetSalt: TBytes;
begin
  SetLength(result, PKCS5_SALT_LEN);
  RAND_pseudo_bytes(@result[0], PKCS5_SALT_LEN);
end;

procedure EVP_GetKeyIV(const APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes;
  out Key, IV: TBytes);
begin
  SetLength(Key, EVP_MAX_KEY_LENGTH);
  SetLength(iv, EVP_MAX_IV_LENGTH);

  EVP_BytesToKey(ACipher, EVP_md5, @ASalt[0], @APassword[0], Length(APassword), 1, @Key[0], @IV[0]);
end;

procedure EVP_GetKeyIV(const APassword: string; ACipher: PEVP_CIPHER; const ASalt: TBytes;
  out Key, IV: TBytes);
var
  B: TBytes;
begin
  B := TEncoding.UTF8.GetBytes(APassword);
  EVP_GetKeyIV(B, ACipher, ASalt, Key, IV);
end;

function LastOpenSSLError: string;
var
  ErrCode: Integer;
begin
  ErrCode := ERR_get_error;
  Result := SSL_error(ErrCode);
end;

procedure RaiseOpenSSLError(const AMessage: string);
var
  ErrCode: Integer;
  ErrMsg, FullMsg: string;
begin
  ErrCode := ERR_get_error;
  ErrMsg := SSL_error(ErrCode);
  if AMessage = '' then
    FullMsg := ErrMsg
  else FullMsg := AMessage + ': ' + ErrMsg;
  raise EOpenSSLError.Create(ErrCode, FullMsg);
end;

{ EOpenSSLError }

constructor EOpenSSLError.Create(AErrorCode: Integer; const AMessage: string);
begin
  FErrorCode := AErrorCode;
  inherited Create(AMessage);
end;

{ TOpenSSLBase }

constructor TOpenSSLBase.Create;
begin
  inherited;
end;

end.
