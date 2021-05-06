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

unit OpenSSL.RSAUtils;

interface

uses
  System.SysUtils, System.Classes, ssl_types, OpenSSL.Core;

type
  TX509Cerificate = class;

  TRSAPassphraseEvent = procedure (Sender: TObject; var Passphrase: string) of object;

  TRSAKey = class(TOpenSLLBase)
  public
    function  IsValid: Boolean; virtual; abstract;
    procedure LoadFromFile(const FileName: string); virtual; abstract;
    procedure LoadFromStream(AStream: TStream); virtual; abstract;
  end;

  // RSA public key
  TRSAPublicKey = class(TRSAKey)
  private
    FBuffer: TBytes;
    FRSA: PRSA;
    FCerificate: TX509Cerificate;
  private
    function  GetRSA: PRSA;
    procedure FreeRSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  Print: string;
    function  IsValid: Boolean; override;
    procedure LoadFromFile(const FileName: string); override;
    procedure LoadFromStream(AStream: TStream); override;
    procedure LoadFromCertificate(Cerificate: TX509Cerificate);
  end;

  // RSA private key
  TRSAPrivateKey = class(TRSAKey)
  private
    FBuffer: TBytes;
    FRSA: PRSA;
    FOnNeedPassphrase: TRSAPassphraseEvent;
  private
    function  GetRSA: PRSA;
    procedure FreeRSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  IsValid: Boolean; override;
    function  Print: string;
    procedure LoadFromFile(const FileName: string); override;
    procedure LoadFromStream(AStream: TStream); override;
    property  OnNeedPassphrase: TRSAPassphraseEvent read FOnNeedPassphrase write FOnNeedPassphrase;
  end;

  // certificate containing an RSA public key
  TX509Cerificate = class(TOpenSLLBase)
  private
    FBuffer: TBytes;
    FPublicRSA: PRSA;
    FX509: pX509;
  private
    function  GetPublicRSA: PRSA;
    procedure FreeRSA;
    procedure FreeX509;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  IsValid: Boolean;
    function  Print: string;
    procedure LoadFromFile(const FileName: string);
    procedure LoadFromStream(AStream: TStream);
  end;

  TRSAUtil = class(TOpenSLLBase)
  private
    FPublicKey: TRSAPublicKey;
    FPrivateKey: TRSAPrivateKey;
  public
    constructor Create; override;
    destructor Destroy; override;

    procedure PublicEncrypt(InputStream: TStream; OutputStream: TStream; Padding: TRASPadding = rpPKCS); overload;
    procedure PublicEncrypt(const InputFileName, OutputFileName: TFileName; Padding: TRASPadding = rpPKCS); overload;
    procedure PrivateDecrypt(InputStream: TStream; OutputStream: TStream; Padding: TRASPadding = rpPKCS); overload;
    procedure PrivateDecrypt(const InputFileName, OutputFileName: TFileName; Padding: TRASPadding = rpPKCS); overload;

    property  PublicKey: TRSAPublicKey read FPublicKey;
    property  PrivateKey: TRSAPrivateKey read FPrivateKey;
  end;

implementation

uses
  ssl_bio, ssl_evp, ssl_pem, ssl_rsa, ssl_x509, OpenSSL.LibEay32;

const
  RSA_PKCS1_PADDING      = 1;
  RSA_SSLV23_PADDING     = 2;
  RSA_NO_PADDING         = 3;
  RSA_PKCS1_OAEP_PADDING = 4;

{ TRSA }

const
  PaddingMap : array [TRASPadding] of Integer = (RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, RSA_NO_PADDING);

// rwflag is a flag set to 0 when reading and 1 when writing
// The u parameter has the same value as the u parameter passed to the PEM routines
function ReadKeyCallback(buf: PAnsiChar; buffsize: Integer; rwflag: Integer; u: Pointer): Integer; cdecl;

  function StrLCopy(Dest: PAnsiChar; const Source: PAnsiChar; MaxLen: Cardinal): PAnsiChar;
  var
    Len: Cardinal;
  begin
    Result := Dest;
    Len := StrLen(Source);
    if Len > MaxLen then
      Len := MaxLen;
    Move(Source^, Dest^, Len * SizeOf(AnsiChar));
    Dest[Len] := #0;
  end;
var
  Len: Integer;
  Password: string;
  PrivateKey: TRSAPrivateKey;
begin
  Result := 0;
  if Assigned(u) then
  begin
    PrivateKey := TRSAPrivateKey(u);
    if Assigned(PrivateKey.FOnNeedPassphrase) then
    begin
      PrivateKey.FOnNeedPassphrase(PrivateKey, Password);
      if Length(Password) < buffsize then
        Len := Length(Password)
      else
        Len := buffsize;
      StrPLCopy(buf, AnsiString(Password), Len);
      Result := Len;
    end;
  end;
end;

procedure TRSAUtil.PublicEncrypt(InputStream, OutputStream: TStream; Padding: TRASPadding);
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  RSAOutLen: Integer;
begin
  if not PublicKey.IsValid then
    raise Exception.Create('Public key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  RSAOutLen := RSA_size(FPublicKey.GetRSA);
  SetLength(OutputBuffer, RSAOutLen);

  RSAOutLen := RSA_public_encrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPublicKey.GetRSA, PaddingMap[Padding]);

  if RSAOutLen <= 0 then
    RaiseOpenSSLError('RSA operation error');

  OutputStream.Write(OutputBuffer[0], RSAOutLen);
end;

constructor TRSAUtil.Create;
begin
  inherited;
  FPublicKey := TRSAPublicKey.Create;
  FPrivateKey := TRSAPrivateKey.Create;
end;

destructor TRSAUtil.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

procedure TRSAUtil.PrivateDecrypt(InputStream, OutputStream: TStream;
  Padding: TRASPadding);
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  RSAOutLen: Integer;
begin
  if not PrivateKey.IsValid then
    raise Exception.Create('Private key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  RSAOutLen := RSA_size(FPrivateKey.GetRSA);
  SetLength(OutputBuffer, RSAOutLen);

  RSAOutLen := RSA_private_decrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPrivateKey.GetRSA, PaddingMap[Padding]);

  if RSAOutLen <= 0 then
    RaiseOpenSSLError('RSA operation error');

  OutputStream.Write(OutputBuffer[0], RSAOutLen);
end;

procedure TRSAUtil.PrivateDecrypt(const InputFileName,
  OutputFileName: TFileName; Padding: TRASPadding);
var
  InputFile, OutputFile: TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      PrivateDecrypt(InputFile, OutputFile, Padding);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

procedure TRSAUtil.PublicEncrypt(const InputFileName, OutputFileName: TFileName;
  Padding: TRASPadding);
var
  InputFile, OutputFile: TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      PublicEncrypt(InputFile, OutputFile, Padding);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

{ TX509Cerificate }

constructor TX509Cerificate.Create;
begin
  inherited;
  FPublicRSA := nil;
end;

destructor TX509Cerificate.Destroy;
begin
  FreeRSA;
  FreeX509;
  inherited;
end;

procedure TX509Cerificate.FreeRSA;
begin
  if FPublicRSA <> nil then
  begin
    RSA_free(FPublicRSA);
    FPublicRSA := nil;
  end;
end;

procedure TX509Cerificate.FreeX509;
begin
  if FX509 <> nil then
    X509_free(FX509);
end;

function TX509Cerificate.GetPublicRSA: PRSA;
var
  Key: pEVP_PKEY;
begin
  if not Assigned(FPublicRSA) then
  begin
    Key := X509_get_pubkey(FX509);
    try
      FPublicRSA := EVP_PKEY_get1_RSA(Key);
      if not Assigned(FPublicRSA) then
        RaiseOpenSSLError('X501 unable to read public key');
    finally
      EVP_PKEY_free(Key);
    end;
  end;

  Result := FPublicRSA;
end;

function TX509Cerificate.IsValid: Boolean;
begin
  Result := Assigned(FX509);
end;

function TX509Cerificate.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetPublicRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TX509Cerificate.LoadFromFile(const FileName: string);
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

procedure TX509Cerificate.LoadFromStream(AStream: TStream);
var
  KeyFile: pBIO;
begin
  FreeRSA;
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

{ TRSAPrivateKey }

constructor TRSAPrivateKey.Create;
begin
  inherited;
  FRSA := nil;
end;

destructor TRSAPrivateKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

procedure TRSAPrivateKey.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

function TRSAPrivateKey.GetRSA: PRSA;
begin
//  if Assigned(FCerificate) then
//    Result := FCerificate.GetPublicRSA
//  else
    Result := FRSA;
end;

function TRSAPrivateKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

function TRSAPrivateKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, FRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TRSAPrivateKey.LoadFromFile(const FileName: string);
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

procedure TRSAPrivateKey.LoadFromStream(AStream: TStream);
var
  KeyBuffer: pBIO;
  cb : pem_password_cb;
begin
  cb := nil;

  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));

  if KeyBuffer = nil then
    RaiseOpenSSLError('RSA load stream error');
  try
    if Assigned(FOnNeedPassphrase) then
      cb := @ReadKeyCallback;
    FRSA := PEM_read_bio_RSAPrivateKey(KeyBuffer, nil, cb, Self);
    if not Assigned(FRSA) then
      RaiseOpenSSLError('RSA load private key error');
  finally
    BIO_free(KeyBuffer);
  end;
end;

{ TRSAPublicKey }

constructor TRSAPublicKey.Create;
begin
  inherited;
  FRSA := nil;
end;

destructor TRSAPublicKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

procedure TRSAPublicKey.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

function TRSAPublicKey.GetRSA: PRSA;
begin
  if Assigned(FCerificate) then
    Result := FCerificate.GetPublicRSA
  else
    Result := FRSA;
end;

function TRSAPublicKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

procedure TRSAPublicKey.LoadFromCertificate(Cerificate: TX509Cerificate);
begin
  FCerificate := Cerificate;
end;

procedure TRSAPublicKey.LoadFromFile(const FileName: string);
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

procedure TRSAPublicKey.LoadFromStream(AStream: TStream);
var
  KeyBuffer: pBIO;
  pKey: PEVP_PKEY;
begin
  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyBuffer = nil then
    RaiseOpenSSLError('RSA load stream error');
  try
// Does'n work
//    FRSA := PEM_read_bio_RSAPublicKey(KeyFile, nil, nil, nil);
//    if not Assigned(FRSA) then
//      RaiseOpenSSLError('RSA load public key error');
    pKey := PEM_read_bio_PUBKEY(KeyBuffer, nil, nil, nil);
    if not Assigned(pKey) then
      RaiseOpenSSLError('PUBKEY load public key error');

    try
      FRSA := EVP_PKEY_get1_RSA(pKey);

      if not Assigned(FRSA) then
        RaiseOpenSSLError('RSA load public key error');
    finally
      EVP_PKEY_free(pKey);
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;

function TRSAPublicKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, FRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

end.
