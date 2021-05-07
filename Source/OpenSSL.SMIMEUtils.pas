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

// enc - symmetric cipher routines
// https://www.openssl.org/docs/manmaster/apps/enc.html

unit OpenSSL.SMIMEUtils;

interface

uses
  System.SysUtils, System.Classes, OpenSSL.Core;

type
  TSMIMEUtil = class(TOpenSSLBase)
  public
    function Decrypt(InputStream, OutputStream: TStream; Verify, NoVerify: Boolean): Integer;
  end;

implementation

uses
  OpenSSL.Api_11;

type
  TC_INT   = LongInt;
  TC_LONG  = LongInt;
  TC_ULONG = LongWord;

  BIO_METHOD = record
    _type : TC_INT;
    name : PAnsiChar;
    bwrite : function(_para1 : PBIO; _para2 : PAnsiChar; _para3 : TC_Int) : TC_Int; cdecl;
    bread : function(_para1: PBIO; _para2: PAnsiChar; _para3: TC_Int) : TC_Int; cdecl;
    bputs : function (_para1 : PBIO; _para2 : PAnsiChar) : TC_Int; cdecl;
    bgets : function (_para1 : PBIO; _para2 : PAnsiChar; _para3 : TC_Int) : TC_Int; cdecl;
    ctrl : function (_para1 : PBIO; _para2 : TC_Int; _para3 : TC_LONG; _para4 : Pointer) : TC_LONG; cdecl;
    create : function(_para1 : PBIO) : TC_Int; cdecl;
    destroy : function (_para1 : PBIO) : TC_Int; cdecl;
    callback_ctrl : function (_para1 : PBIO; _para2 : TC_Int; _para3 : pbio_info_cb): TC_LONG; cdecl;
  end;

  BIO = record
    method : PBIO_METHOD;
    callback : function (_para1 : PBIO; _para2 : TC_INT; _para3 : PAnsiChar;
       _para4 : TC_INT; _para5, _para6 : TC_LONG) : TC_LONG cdecl;
    cb_arg : PAnsiChar;
    init : TC_INT;
    shutdown : TC_INT;
    flags : TC_INT;
    retry_reason : TC_INT;
    num : TC_INT;
    ptr : Pointer;
    next_bio : PBIO;
    prev_bio : PBIO;
    references : TC_INT;
    num_read : TC_ULONG;
    num_write : TC_ULONG;
    ex_data : CRYPTO_EX_DATA;
  end;
  PBIO = ^BIO;

{ TSMIMEUtil }

function TSMIMEUtil.Decrypt(InputStream, OutputStream: TStream; Verify, NoVerify: Boolean): Integer;
var
  LInput, LOutput, LContent: PBIO;
  LPKCS7: PPKCS7;
  LStore: PX509_STORE;
  LCerts: PSTACK_OF_X509;
  LFlags, LOutputLen: Integer;
  LOutputBuffer, LInputBuffer: TBytes;
begin
  Result := 0;
  LFlags := 0;
  if NoVerify then
    LFlags := PKCS7_NOVERIFY;
  LContent := nil;
  LCerts := nil;
  LInput := nil;
  LOutput := nil;
  LStore := X509_STORE_new();
  try
    SetLength(LInputBuffer, InputStream.Size);
    InputStream.ReadBuffer(LInputBuffer[0], InputStream.Size);

    LInput := BIO_new_mem_buf(LInputBuffer, InputStream.Size);
    if not Assigned(LInput) then
      RaiseOpenSSLError('BIO_new_file');

    LPKCS7 := nil;
    LPKCS7 := d2i_PKCS7_bio(LInput, @LPKCS7);

    if not Assigned(LPKCS7) then
      RaiseOpenSSLError('FSMIME_read_PKCS7');

    LOutput := BIO_new(BIO_s_mem());
    if not Assigned(LOutput) then
      RaiseOpenSSLError('BIO_new');

    if Verify then
    begin
      Result := PKCS7_verify(LPKCS7, LCerts, LStore, LContent, LOutput, LFlags);

      if Assigned(LOutput) and Assigned(OutputStream) then
      begin
        LOutputLen := LOutput.num_write;
        SetLength(LOutputBuffer, LOutputLen);
        BIO_read(LOutput, LOutputBuffer, LOutputLen);

        OutputStream.WriteBuffer(LOutputBuffer, LOutputLen);
      end;
    end;
  finally
    BIO_free(LInput);
    BIO_free(LOutput);
    BIO_free(LContent);
  end;
end;

end.
