{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2021 Lsuper                                                   }
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

unit OpenSSL.HashUtils;

// https://www.openssl.org/docs/man1.1.1/man3/MD4.html
// https://www.openssl.org/docs/man1.1.1/man3/MD5.html
// https://www.openssl.org/docs/man1.1.1/man3/SHA1.html
// https://www.openssl.org/docs/man1.1.1/man3/SHA256.html

interface

uses
  System.SysUtils, OpenSSL.Api_11;

type
  // handle MD4 hashing
  TMD4 = record
  private
    FContext: MD4_CTX;
  public
    // initialize MD4 context for hashing
    procedure Init;
    // update the MD4 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer);
    // finalize and compute the resulting MD4 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes);
  end;

  // handle MD5 hashing
  TMD5 = record
  private
    FContext: MD5_CTX;
  public
    // initialize MD5 context for hashing
    procedure Init;
    // update the MD5 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer);
    // finalize and compute the resulting MD5 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes);
  end;

  /// handle SHA1 hashing
  TSHA1 = record
  private
    FContext: SHA_CTX;
  public
    // initialize SHA1 context for hashing
    procedure Init;
    // update the SHA1 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer);
    // finalize and compute the resulting SHA1 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes);
  end;

  /// handle SHA256 hashing
  TSHA256 = record
  private
    FContext: SHA256_CTX;
  public
    // initialize SHA256 context for hashing
    procedure Init;
    // update the SHA256 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer);
    // finalize and compute the resulting SHA256 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes);
  end;

implementation

uses
  OpenSSL.Core;

{ TMD4 }

procedure TMD4.Final(out ADigest: TBytes);
begin
  SetLength(ADigest, MD4_DIGEST_LENGTH);
  MD4_Final(PByte(ADigest), @FContext);
end;

procedure TMD4.Init;
begin
  MD4_Init(@FContext);
end;

procedure TMD4.Update(ABuffer: Pointer; ASize: integer);
begin
  MD4_Update(@FContext, ABuffer, ASize);
end;

{ TMD5 }

procedure TMD5.Final(out ADigest: TBytes);
begin
  SetLength(ADigest, MD5_DIGEST_LENGTH);
  MD5_Final(PByte(ADigest), @FContext);
end;

procedure TMD5.Init;
begin
  MD5_Init(@FContext);
end;

procedure TMD5.Update(ABuffer: Pointer; ASize: integer);
begin
  MD5_Update(@FContext, ABuffer, ASize);
end;

{ TSHA1 }

procedure TSHA1.Final(out ADigest: TBytes);
begin
  SetLength(ADigest, SHA_DIGEST_LENGTH);
  SHA1_Final(PByte(ADigest), @FContext);
end;

procedure TSHA1.Init;
begin
  SHA1_Init(@FContext);
end;

procedure TSHA1.Update(ABuffer: Pointer; ASize: integer);
begin
  SHA1_Update(@FContext, ABuffer, ASize);
end;

{ TSHA256 }

procedure TSHA256.Final(out ADigest: TBytes);
begin
  SetLength(ADigest, SHA256_DIGEST_LENGTH);
  SHA256_Final(PByte(ADigest), @FContext);
end;

procedure TSHA256.Init;
begin
  SHA256_Init(@FContext);
end;

procedure TSHA256.Update(ABuffer: Pointer; ASize: integer);
begin
  SHA256_Update(@FContext, ABuffer, ASize);
end;

end.
