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

unit OpenSSL.LibEay32;

interface

uses
  System.SysUtils, ssl_types;

function BIO_to_string(b: PBIO; Encoding: TEncoding): string; overload;
function BIO_to_string(b: PBIO): string; overload;

function LoadOpenSSLLibraryEx: Boolean;

implementation

uses
  Winapi.Windows, ssl_bio, ssl_err, ssl_evp, ssl_pem, ssl_pkcs7, ssl_rand,
  ssl_dsa, ssl_rsa, ssl_util, ssl_x509;

const
  LIBEAY_DLL_NAME = 'libeay32.dll';

var
  hSSL: HMODULE;

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

////////////////////////////////////////////////////////////////////////////////
//设计：Lsuper 2017.12.06
//功能：
//参数：
////////////////////////////////////////////////////////////////////////////////
function LoadOpenSSLLibraryEx: Boolean;
begin
  if hSSL <> 0 then
  begin
    Result := True;
    Exit;
  end;
  hSSL := LoadLibrary(LIBEAY_DLL_NAME);
  if hSSL = 0 then
  begin
    Result := False;
    Exit;
  end;

  SSL_InitBIO;
  SSL_InitERR;
  SSL_InitEVP;
  SSL_InitPEM;
  SSL_InitPKCS7;
  SSL_InitRAND;
  SSL_InitDSA;
  SSL_InitRSA;
  SSL_InitUtil;
  SSL_InitX509;

  OPENSSL_add_all_algorithms_noconf; { OpenSSL_add_all_algorithms }
  OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests;
  ERR_load_crypto_strings;

  Result := True;
end;

procedure UnLoadOpenSSLLibraryEx;
begin
  if hSSL <> 0 then
    FreeLibrary(hSSL);
end;

initialization
  ;

finalization
  UnLoadOpenSSLLibraryEx;

end.
