{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
{  https://bitbucket.org/lminuti/delphi-openssl                                }
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

  function  Base64Encode(const ABuffer: TBytes;
    AWrapLines: Boolean = False): TBytes;
  function  Base64Decode(const ABuffer: TBytes): TBytes;

  function  BufferToHex(const ABuffer; ASize: Integer;
    ALowerCase: Boolean = True): string;
  function  BytesToHex(const AData: TBytes;
    ALowerCase: Boolean = True): string;
  function  HexToBytes(const ABuffer; ASize: Integer): TBytes; overload;
  function  HexToBytes(const S: string): TBytes; overload;

  function  BIO_flush(b: PBIO): Integer;
  function  BIO_get_mem_data(b: PBIO; pp: Pointer): Integer;
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

function Base64Encode(const ABuffer: TBytes; AWrapLines: Boolean = False): TBytes;
var
  bio, b64: PBIO;
  bdata: Pointer;
  datalen: Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  if not AWrapLines then
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio := BIO_new(BIO_s_mem());
  BIO_push(b64, bio);

  BIO_write(b64, @ABuffer[0], Length(ABuffer));
  BIO_flush(b64);

  bdata := nil;
  datalen := BIO_get_mem_data(bio, @bdata);
  SetLength(Result, datalen);
  Move(bdata^, Result[0], datalen);

  BIO_free_all(b64);
end;

function Base64Decode(const ABuffer: TBytes): TBytes;
var
  bio, b64: PBIO;
  datalen: Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new_mem_buf(ABuffer, Length(ABuffer));
  try
    BIO_push(b64, bio);

    SetLength(Result, Length(ABuffer));
    datalen := BIO_read(b64, @Result[0], Length(ABuffer));
    if datalen < 0 then
      RaiseOpenSSLError('Base64 error');

    SetLength(Result, datalen);
    BIO_flush(b64);
  finally
    BIO_free_all(b64);
  end;
end;

function BufferToHex(const ABuffer; ASize: Integer; ALowerCase: Boolean): string;
type
  PHexCharMap = ^THexCharMap;
  THexCharMap = array[0..15] of Char;
const
  defCharConvertTableL: THexCharMap = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  );
  defCharConvertTableU: THexCharMap = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  );
var
  pData: PByte;
  pRet: PChar;
  pMap: PHexCharMap;
begin
  if ALowerCase then
    pMap := @defCharConvertTableL
  else pMap := @defCharConvertTableU;
  pData := @ABuffer;
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

function BytesToHex(const AData: TBytes; ALowerCase: Boolean = True): string;
begin
  Result := BufferToHex(Pointer(AData)^, Length(AData), ALowerCase);
end;

function HexToBytes(const ABuffer; ASize: Integer): TBytes;

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
  pData := @ABuffer;
  while nIndex < nLen do
  begin
    Result[nIndex] := HexWordToByte(pData^);
    Inc(pData);
    Inc(nIndex);
  end;
end;

function HexToBytes(const S: string): TBytes;
var
  B: TBytes;
begin
  B := TEncoding.Default.GetBytes(S);
  Result := HexToBytes(Pointer(B)^, Length(B));
end;

function BIO_flush(b: PBIO): Integer;
begin
  Result := BIO_ctrl(b, BIO_CTRL_FLUSH, 0, nil);
end;

function BIO_get_mem_data(b: PBIO; pp: Pointer): Integer;
begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
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
