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
    constructor Create(Code: Integer; const Msg: string);

    property  ErrorCode: Integer read FErrorCode;
  end;

  TOpenSLLBase = class(TObject)
  public
    constructor Create; virtual;
  end;

  function  Base64Encode(const InputBuffer: TBytes): TBytes;
  function  Base64Decode(const InputBuffer: TBytes): TBytes;

  function  BIO_flush(b: PBIO): Integer;
  function  BIO_get_mem_data(b: PBIO; pp: Pointer): Integer;
  function  BIO_to_string(b: PBIO; Encoding: TEncoding): string; overload;
  function  BIO_to_string(b: PBIO): string; overload;

  function  EVP_GetSalt: TBytes;
  procedure EVP_GetKeyIV(APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes); overload;
  { Password will be encoded in UTF-8 if you want another encodig use the TBytes version }
  procedure EVP_GetKeyIV(APassword: string; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes); overload;

  function  LastOpenSSLError: string;
  procedure RaiseOpenSSLError(const AMessage: string = '');

implementation

function Base64Encode(const InputBuffer: TBytes): TBytes;
var
  bio, b64: PBIO;
  bdata: Pointer;
  datalen: Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new(BIO_s_mem());
  BIO_push(b64, bio);

  BIO_write(b64, @InputBuffer[0], Length(InputBuffer));
  BIO_flush(b64);

  bdata := nil;
  datalen := BIO_get_mem_data(bio, @bdata);
  SetLength(Result, datalen);
  Move(bdata^, Result[0], datalen);

  BIO_free_all(b64);
end;

function Base64Decode(const InputBuffer: TBytes): TBytes;
var
  bio, b64: PBIO;
  datalen: Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new_mem_buf(InputBuffer, Length(InputBuffer));
  try
    BIO_push(b64, bio);

    SetLength(Result, Length(InputBuffer));
    datalen := BIO_read(b64, @Result[0], Length(InputBuffer));
    if datalen < 0 then
      RaiseOpenSSLError('Base64 error');

    SetLength(Result, datalen);
    BIO_flush(b64);
  finally
    BIO_free_all(b64);
  end;
end;

function BIO_flush(b : PBIO): Integer;
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

procedure EVP_GetKeyIV(APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes);
begin
  SetLength(Key, EVP_MAX_KEY_LENGTH);
  SetLength(iv, EVP_MAX_IV_LENGTH);

  EVP_BytesToKey(ACipher,EVP_md5, @ASalt[0] ,@APassword[0]  , Length(APassword),1, @Key[0], @IV[0]);
end;

procedure EVP_GetKeyIV(APassword: string; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes);
begin
  EVP_GetKeyIV(TEncoding.UTF8.GetBytes(APassword), ACipher, ASalt, Key, IV);
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

{ TOpenSLLBase }

constructor TOpenSLLBase.Create;
begin
  inherited;
end;

{ EOpenSSLError }

constructor EOpenSSLError.Create(Code: Integer; const Msg: string);
begin
  FErrorCode := Code;
  inherited Create(Msg);
end;

end.
