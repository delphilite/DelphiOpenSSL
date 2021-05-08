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
  System.SysUtils, System.Classes, OpenSSL.Api_11, OpenSSL.Core;

type
  THashUtil = class(TOpenSSLBase)
  public
    // initialize Hash context for hashing
    procedure Init; virtual; abstract;
    // update the Hash context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); virtual; abstract;
    // update the Hash context with stream data
    procedure UpdateStream(AStream: TStream; const ACount: Int64 = 0);
    // finalize and compute the resulting Hash hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); virtual; abstract;
  public
    // portal for stream
    class function Execute(AStream: TStream; const ACount: Int64 = 0): TBytes; overload;
    // portal for bytes
    class function Execute(const AData: TBytes): TBytes; overload;
  end;

  // handle MD4 hashing
  TMD4 = class(THashUtil)
  private
    FContext: MD4_CTX;
  public
    // initialize MD4 context for hashing
    procedure Init; override;
    // update the MD4 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); override;
    // finalize and compute the resulting MD4 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); override;
  end;

  // handle MD5 hashing
  TMD5 = class(THashUtil)
  private
    FContext: MD5_CTX;
  public
    // initialize MD5 context for hashing
    procedure Init; override;
    // update the MD5 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); override;
    // finalize and compute the resulting MD5 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); override;
  end;

  /// handle SHA1 hashing
  TSHA1 = class(THashUtil)
  private
    FContext: SHA_CTX;
  public
    // initialize SHA1 context for hashing
    procedure Init; override;
    // update the SHA1 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); override;
    // finalize and compute the resulting SHA1 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); override;
  end;

  /// handle SHA256 hashing
  TSHA256 = class(THashUtil)
  private
    FContext: SHA256_CTX;
  public
    // initialize SHA256 context for hashing
    procedure Init; override;
    // update the SHA256 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); override;
    // finalize and compute the resulting SHA256 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); override;
  end;

  /// handle SHA512 hashing
  TSHA512 = class(THashUtil)
  private
    FContext: SHA512_CTX;
  public
    // initialize SHA512 context for hashing
    procedure Init; override;
    // update the SHA512 context with some data
    procedure Update(ABuffer: Pointer; ASize: integer); override;
    // finalize and compute the resulting SHA512 hash Digest of all data
    // affected to Update() method
    procedure Final(out ADigest: TBytes); override;
  end;

implementation

uses
  System.Math;

{ THashUtil }

class function THashUtil.Execute(const AData: TBytes): TBytes;
begin
  with Self.Create do
  try
    Init;
    Update(Pointer(AData), Length(AData));
    Final(Result);
  finally
    Free;
  end;
end;

class function THashUtil.Execute(AStream: TStream; const ACount: Int64): TBytes;
begin
  with Self.Create do
  try
    Init;
    UpdateStream(AStream, ACount);
    Final(Result);
  finally
    Free;
  end;
end;

procedure THashUtil.UpdateStream(AStream: TStream; const ACount: Int64);
const
  defBufferSize = 1024 * 1024; { 1m }
var
  B: TBytes;
  L, R: Integer;
  C: Int64;
begin
  if ACount = 0 then
    C := AStream.Size - AStream.Position
  else C := Min(ACount, AStream.Size - AStream.Position);
  SetLength(B, defBufferSize);
  while C > 0 do
  begin
    L := Min(C, defBufferSize);
    R := AStream.Read(Pointer(B)^, L);
    Update(Pointer(B), R);
    Dec(C, R);
  end;
end;

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

{ TSHA512 }

procedure TSHA512.Final(out ADigest: TBytes);
begin
  SetLength(ADigest, SHA512_DIGEST_LENGTH);
  SHA512_Final(PByte(ADigest), @FContext);
end;

procedure TSHA512.Init;
begin
  SHA512_Init(@FContext);
end;

procedure TSHA512.Update(ABuffer: Pointer; ASize: integer);
begin
  SHA512_Update(@FContext, ABuffer, ASize);
end;

end.
