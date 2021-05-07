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

unit OpenSSL.DSAUtils;

// https://www.openssl.org/docs/man1.1.1/man3/DSA_sign.html
// https://www.openssl.org/docs/man1.1.1/man3/DSA_verify.html

interface

uses
  System.SysUtils, System.Classes, OpenSSL.Core, OpenSSL.Api_11;

type
  // DSA base key
  TDSAKey = class(TOpenSSLBase)
  public
    function  IsValid: Boolean; virtual; abstract;
    procedure LoadFromFile(const FileName: string); virtual; abstract;
    procedure LoadFromStream(AStream: TStream); virtual; abstract;
  end;

  // DSA public key
  TDSAPublicKey = class(TDSAKey)
  private
    FBuffer: TBytes;
    FDSA: PDSA;
  private
    function  GetDSA: PDSA;
    procedure FreeDSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  Print: string;
    function  IsValid: Boolean; override;
    procedure LoadFromFile(const FileName: string); override;
    procedure LoadFromStream(AStream: TStream); override;
  end;

  // DSA private key
  TDSAPrivateKey = class(TDSAKey)
  private
    FBuffer: TBytes;
    FDSA: PDSA;
  private
    function  GetDSA: PDSA;
    procedure FreeDSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  IsValid: Boolean; override;
    function  Print: string;
    procedure LoadFromFile(const FileName: string); override;
    procedure LoadFromStream(AStream: TStream); override;
  end;

  // Certificate containing an DSA public key
  TDSACerificate = class(TOpenSSLBase)
  private
    FBuffer: TBytes;
    FPublicDSA: PDSA;
    FX509: pX509;
  private
    function  GetPublicDSA: PDSA;
    procedure FreeDSA;
    procedure FreeX509;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  IsValid: Boolean;
    function  Print: string;
    procedure LoadFromFile(const FileName: string);
    procedure LoadFromStream(AStream: TStream);
  end;

  TDSAUtil = class(TOpenSSLBase)
  private
    FPublicKey: TDSAPublicKey;
    FPrivateKey: TDSAPrivateKey;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  PublicVerify(const Input, Output: TBytes): Boolean; overload;
    function  PrivateSign(const Input: TBytes): TBytes; overload;

    function  PublicVerify(InputStream: TStream; OutputStream: TStream): Boolean; overload;
    procedure PrivateSign(InputStream: TStream; OutputStream: TStream); overload;

    function  PublicVerify(const InputFileName, OutputFileName: TFileName): Boolean; overload;
    procedure PrivateSign(const InputFileName, OutputFileName: TFileName); overload;

    property  PublicKey: TDSAPublicKey read FPublicKey;
    property  PrivateKey: TDSAPrivateKey read FPrivateKey;
  end;

implementation

{ TDSAUtil }

constructor TDSAUtil.Create;
begin
  inherited;
  FPublicKey := TDSAPublicKey.Create;
  FPrivateKey := TDSAPrivateKey.Create;
end;

destructor TDSAUtil.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

function TDSAUtil.PrivateSign(const Input: TBytes): TBytes;
var
  Output: TBytes;
  OutLen, Ret: Integer;
begin
  if not PrivateKey.IsValid then
    raise Exception.Create('Private key not assigned');
  if (Input = nil) or (Length(Input) = 0) then
  begin
    Result := nil;
    Exit;
  end;
  OutLen := 1024; { DSA_size(FPrivateKey.GetDSA) }
  SetLength(Output, OutLen);
  Ret := DSA_sign(0, PByte(Input), Length(Input), PByte(Output), @OutLen, FPrivateKey.GetDSA);
  if Ret <> 1 then
    RaiseOpenSSLError('DSA sign error');
  if OutLen <= 0 then
    RaiseOpenSSLError('DSA operation error');
  Result := Copy(Output, 0, OutLen);
end;

procedure TDSAUtil.PrivateSign(const InputFileName, OutputFileName: TFileName);
var
  InputFile, OutputFile: TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead or fmShareDenyWrite);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      PrivateSign(InputFile, OutputFile);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

procedure TDSAUtil.PrivateSign(InputStream, OutputStream: TStream);
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  Ret, DSAOutLen: Integer;
begin
  if not PrivateKey.IsValid then
    raise Exception.Create('Private key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  DSAOutLen := 1024; { DSA_size(FPrivateKey.GetDSA) }
  SetLength(OutputBuffer, DSAOutLen);

  Ret := DSA_sign(0, PByte(InputBuffer), Length(InputBuffer), PByte(OutputBuffer), @DSAOutLen, FPrivateKey.GetDSA);
  if Ret <> 1 then
    RaiseOpenSSLError('DSA sign error');

  SetLength(OutputBuffer, DSAOutLen);

  if DSAOutLen <= 0 then
    RaiseOpenSSLError('DSA operation error');

  OutputStream.Write(OutputBuffer[0], DSAOutLen);
end;

function TDSAUtil.PublicVerify(const Input, Output: TBytes): Boolean;
var
  Ret: Integer;
begin
  if not PublicKey.IsValid then
    raise Exception.Create('Public key not assigned');
  if (Input = nil) or (Length(Input) = 0) then
  begin
    Result := Length(Output) = 0;
    Exit;
  end;
  Ret := DSA_verify(0, PByte(Input), Length(Input), PByte(Output), Length(Output), FPublicKey.GetDSA);
  Result := Ret = 1;
  if Ret <= 0 then
    RaiseOpenSSLError('DSA operation error');
end;

function TDSAUtil.PublicVerify(const InputFileName, OutputFileName: TFileName): Boolean;
var
  InputFile, OutputFile: TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead or fmShareDenyWrite);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmOpenRead or fmShareDenyWrite);
    try
      Result := PublicVerify(InputFile, OutputFile);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

function TDSAUtil.PublicVerify(InputStream, OutputStream: TStream): Boolean;
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  Ret: Integer;
begin
  if not PublicKey.IsValid then
    raise Exception.Create('Public key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  SetLength(OutputBuffer, OutputStream.Size);
  OutputStream.ReadBuffer(OutputBuffer[0], OutputStream.Size);

  Ret := DSA_verify(0, PByte(InputBuffer), Length(InputBuffer), PByte(OutputBuffer), Length(OutputBuffer), FPublicKey.GetDSA);
  Result := Ret = 1;
  if Ret <= 0 then
    RaiseOpenSSLError('DSA operation error');
end;

{ TDSACerificate }

constructor TDSACerificate.Create;
begin
  inherited;
  FPublicDSA := nil;
end;

destructor TDSACerificate.Destroy;
begin
  FreeDSA;
  FreeX509;
  inherited;
end;

procedure TDSACerificate.FreeDSA;
begin
  if FPublicDSA <> nil then
  begin
    DSA_free(FPublicDSA);
    FPublicDSA := nil;
  end;
end;

procedure TDSACerificate.FreeX509;
begin
  if FX509 <> nil then
    X509_free(FX509);
end;

function TDSACerificate.GetPublicDSA: PDSA;
var
  Key: pEVP_PKEY;
begin
  if not Assigned(FPublicDSA) then
  begin
    Key := X509_get_pubkey(FX509);
    try
      FPublicDSA := EVP_PKEY_get1_DSA(Key);
      if not Assigned(FPublicDSA) then
        RaiseOpenSSLError('X501 unable to read public key');
    finally
      EVP_PKEY_free(Key);
    end;
  end;

  Result := FPublicDSA;
end;

function TDSACerificate.IsValid: Boolean;
begin
  Result := Assigned(FX509);
end;

procedure TDSACerificate.LoadFromFile(const FileName: string);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TDSACerificate.LoadFromStream(AStream: TStream);
var
  KeyFile: pBIO;
begin
  FreeDSA;
  FreeX509;

  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyFile := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyFile = nil then
    RaiseOpenSSLError('X509 load stream error');
  try
    FX509 := PEM_read_bio_X509(KeyFile, nil, nil, nil);
    if not Assigned(FX509) then
      RaiseOpenSSLError('X509 load certificate error');
  finally
    BIO_free(KeyFile);
  end;
end;

function TDSACerificate.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if DSA_print(bp, GetPublicDSA, 0) = 0 then
      RaiseOpenSSLError('DSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

{ TDSAPrivateKey }

constructor TDSAPrivateKey.Create;
begin
  inherited;
  FDSA := nil;
end;

destructor TDSAPrivateKey.Destroy;
begin
  FreeDSA;
  inherited;
end;

procedure TDSAPrivateKey.FreeDSA;
begin
  if FDSA <> nil then
  begin
    DSA_free(FDSA);
    FDSA := nil;
  end;
end;

function TDSAPrivateKey.GetDSA: PDSA;
begin
//  if Assigned(FCerificate) then
//    Result := FCerificate.GetPublicDSA
//  else
    Result := FDSA;
end;

function TDSAPrivateKey.IsValid: Boolean;
begin
  Result := GetDSA <> nil;
end;

procedure TDSAPrivateKey.LoadFromFile(const FileName: string);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TDSAPrivateKey.LoadFromStream(AStream: TStream);
var
  KeyBuffer: pBIO;
begin
  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));

  if KeyBuffer = nil then
    RaiseOpenSSLError('DSA load stream error');
  try
    FDSA := PEM_read_bio_DSAPrivateKey(KeyBuffer, nil, nil, nil);
    if not Assigned(FDSA) then
      RaiseOpenSSLError('DSA load private key error');
  finally
    BIO_free(KeyBuffer);
  end;
end;

function TDSAPrivateKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if DSA_print(bp, FDSA, 0) = 0 then
      RaiseOpenSSLError('DSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

{ TDSAPublicKey }

constructor TDSAPublicKey.Create;
begin
  inherited;
  FDSA := nil;
end;

destructor TDSAPublicKey.Destroy;
begin
  FreeDSA;
  inherited;
end;

procedure TDSAPublicKey.FreeDSA;
begin
  if FDSA <> nil then
  begin
    DSA_free(FDSA);
    FDSA := nil;
  end;
end;

function TDSAPublicKey.GetDSA: PDSA;
begin
  Result := FDSA;
end;

function TDSAPublicKey.IsValid: Boolean;
begin
  Result := GetDSA <> nil;
end;

procedure TDSAPublicKey.LoadFromFile(const FileName: string);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TDSAPublicKey.LoadFromStream(AStream: TStream);
var
  KeyBuffer: pBIO;
begin
  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyBuffer = nil then
    RaiseOpenSSLError('DSA load stream error');
  try
    FDSA := PEM_read_bio_DSA_PUBKEY(KeyBuffer, nil, nil, nil);
    if not Assigned(FDSA) then
      RaiseOpenSSLError('DSA load public key error');
  finally
    BIO_free(KeyBuffer);
  end;
end;

function TDSAPublicKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if DSA_print(bp, FDSA, 0) = 0 then
      RaiseOpenSSLError('DSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

end.
