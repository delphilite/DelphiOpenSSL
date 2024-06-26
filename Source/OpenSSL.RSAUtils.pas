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

unit OpenSSL.RSAUtils;

interface

uses
  System.SysUtils, System.Classes, OpenSSL.Core, OpenSSL.Api_11;

type
  TRSAPadding = (
    rpPKCS,           // use PKCS#1 v1.5 padding (default),
    rpOAEP,           // use PKCS#1 OAEP
    rpSSL,            // use SSL v2 padding
    rpRAW             // use no padding
  );

  TPublicKeyFormat = (
    kfDefault, kfRSAPublicKey
  );

  TPrivateKeyFormat = (
    kpDefault, kpRSAPrivateKey
  );

  TX509Cerificate = class;

  TPassphraseEvent = procedure (Sender: TObject; var Passphrase: string) of object;

  // RSA public key
  TCustomRSAPublicKey = class(TOpenSSLBase)
  private
    FBuffer: TBytes;
    FCerificate: TX509Cerificate;
  protected
    function  GetRSA: PRSA; virtual; abstract;
    procedure FreeRSA; virtual; abstract;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  Print: string;
    function  IsValid: Boolean;

    procedure LoadFromCertificate(Cerificate: TX509Cerificate);

    procedure LoadFromFile(const FileName: string; AFormat: TPublicKeyFormat = kfDefault);
    procedure SaveToFile(const FileName: string; AFormat: TPublicKeyFormat = kfDefault);

    procedure LoadFromStream(AStream: TStream; AFormat: TPublicKeyFormat = kfDefault); virtual;
    procedure SaveToStream(AStream: TStream; AFormat: TPublicKeyFormat = kfDefault); virtual;
  end;

  TRSAPublicKey = class(TCustomRSAPublicKey)
  private
    FRSA: PRSA;
  protected
    function  GetRSA: PRSA; override;
    procedure FreeRSA; override;
  public
    constructor Create; override;

    procedure LoadFromStream(AStream: TStream; AFormat: TPublicKeyFormat = kfDefault); override;
  end;

  // RSA private key
  TCustomRSAPrivateKey = class(TOpenSSLBase)
  private
    FBuffer: TBytes;
    FOnNeedPassphrase: TPassphraseEvent;
  protected
    function  GetRSA: PRSA; virtual; abstract;
    procedure FreeRSA; virtual; abstract;
  public
    constructor Create; override;
    destructor Destroy; override;

    function  IsValid: Boolean;
    function  Print: string;

    procedure LoadFromFile(const FileName: string; AFormat: TPrivateKeyFormat = kpDefault);
    procedure SaveToFile(const FileName: string; AFormat: TPrivateKeyFormat = kpDefault);

    procedure LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault); virtual;
    procedure SaveToStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault); virtual;

    property  OnNeedPassphrase: TPassphraseEvent read FOnNeedPassphrase write FOnNeedPassphrase;
  end;

  TRSAPrivateKey = class(TCustomRSAPrivateKey)
  private
    FRSA: PRSA;
  protected
    function  GetRSA: PRSA; override;
    procedure FreeRSA; override;
  public
    constructor Create; override;

    procedure LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault); override;
  end;

  // certificate containing an RSA public key
  TX509Cerificate = class(TOpenSSLBase)
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

  TRSAKeyPair = class(TOpenSSLBase)
  private
    FRSA: PRSA;
    FPrivateKey: TCustomRSAPrivateKey;
    FPublicKey: TCustomRSAPublicKey;
  private
    procedure FreeRSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    procedure GenerateKey; overload;
    procedure GenerateKey(KeySize: Integer); overload;

    property  PrivateKey: TCustomRSAPrivateKey read FPrivateKey;
    property  PublicKey: TCustomRSAPublicKey read FPublicKey;
  end;

  TRSAHashAlgorithm = (
    haSHA256, haSHA384, haSHA512
  );

  TRSAUtil = class(TOpenSSLBase)
  private const
    PaddingMap: array [TRSAPadding] of Integer = (RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, RSA_NO_PADDING);
  private
    FPublicKey: TCustomRSAPublicKey;
    FPrivateKey: TCustomRSAPrivateKey;
    FOwnedPrivateKey: TCustomRSAPrivateKey;
    FOwnedPublicKey: TCustomRSAPublicKey;
  private
    procedure SetPublicKey(const Value: TCustomRSAPublicKey);
    procedure SetPrivateKey(const Value: TCustomRSAPrivateKey);
  public
    constructor Create; override;
    destructor Destroy; override;

    function  PrivateSign(const Input: TBytes; AAlg: TRSAHashAlgorithm): TBytes;
    function  PublicVerify(const Input, Signature: TBytes; AAlg: TRSAHashAlgorithm): Boolean;

    function  PublicEncrypt(const Input: TBytes; Padding: TRSAPadding = rpPKCS): TBytes; overload;
    function  PrivateDecrypt(const Input: TBytes; Padding: TRSAPadding = rpPKCS): TBytes; overload;

    procedure PublicEncrypt(InputStream: TStream; OutputStream: TStream; Padding: TRSAPadding = rpPKCS); overload;
    procedure PrivateDecrypt(InputStream: TStream; OutputStream: TStream; Padding: TRSAPadding = rpPKCS); overload;

    procedure PublicEncrypt(const InputFileName, OutputFileName: TFileName; Padding: TRSAPadding = rpPKCS); overload;
    procedure PrivateDecrypt(const InputFileName, OutputFileName: TFileName; Padding: TRSAPadding = rpPKCS); overload;

    property  PublicKey: TCustomRSAPublicKey read FPublicKey write SetPublicKey;
    property  PrivateKey: TCustomRSAPrivateKey read FPrivateKey write SetPrivateKey;
  end;

implementation

type
  TRSAKeyPairPrivateKey = class(TCustomRSAPrivateKey)
  private
    FKeyPair: TRSAKeyPair;
  protected
    procedure FreeRSA; override;
    function GetRSA: PRSA; override;
  public
    constructor Create(KeyPair: TRSAKeyPair); reintroduce;
  end;

  TRSAKeyPairPublicKey = class(TCustomRSAPublicKey)
  private
    FKeyPair: TRSAKeyPair;
  protected
    procedure FreeRSA; override;
    function GetRSA: PRSA; override;
  public
    constructor Create(KeyPair: TRSAKeyPair); reintroduce;
  end;

// rwflag is a flag set to 0 when reading and 1 when writing
// The u parameter has the same value as the u parameter passed to the PEM routines
function ReadKeyCallback(buf: PAnsiChar; buffsize: Integer; rwflag: Integer; u: Pointer): Integer; cdecl;
var
  Len: Integer;
  Password: string;
  PrivateKey: TCustomRSAPrivateKey;
begin
  Result := 0;
  if Assigned(u) then
  begin
    PrivateKey := TCustomRSAPrivateKey(u);
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

{ TRSAUtil }

constructor TRSAUtil.Create;
begin
  inherited;
  FOwnedPublicKey := TRSAPublicKey.Create;
  FOwnedPrivateKey := TRSAPrivateKey.Create;

  FPrivateKey := FOwnedPrivateKey;
  FPublicKey := FOwnedPublicKey;
end;

destructor TRSAUtil.Destroy;
begin
  FOwnedPublicKey.Free;
  FOwnedPrivateKey.Free;
  inherited;
end;

function TRSAUtil.PrivateDecrypt(const Input: TBytes; Padding: TRSAPadding): TBytes;
var
  Len: Integer;
begin
  if not FPrivateKey.IsValid then
    raise Exception.Create('RSA prikey not assigned');
  Len := RSA_size(FPrivateKey.GetRSA);
  SetLength(Result, Len);
  Len := RSA_private_decrypt(Length(Input), PByte(Input), PByte(Result), FPrivateKey.GetRSA, PaddingMap[Padding]);
  if Len <= 0 then
    RaiseOpenSSLError('RSA decrypt error');
  SetLength(Result, Len);
end;

procedure TRSAUtil.PrivateDecrypt(const InputFileName, OutputFileName: TFileName; Padding: TRSAPadding);
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

procedure TRSAUtil.PrivateDecrypt(InputStream, OutputStream: TStream; Padding: TRSAPadding);
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  Len: Integer;
begin
  if not FPrivateKey.IsValid then
    raise Exception.Create('RSA prikey not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  Len := RSA_size(FPrivateKey.GetRSA);
  SetLength(OutputBuffer, Len);

  Len := RSA_private_decrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPrivateKey.GetRSA, PaddingMap[Padding]);

  if Len <= 0 then
    RaiseOpenSSLError('RSA decrypt error');

  OutputStream.Write(OutputBuffer[0], Len);
end;

function TRSAUtil.PrivateSign(const Input: TBytes; AAlg: TRSAHashAlgorithm): TBytes;
var
  Ctx: PEVP_MD_CTX;
  MD: PEVP_MD;
  pKey: PEVP_PKEY;
  Size: NativeUInt;
begin
  if not FPrivateKey.IsValid then
    raise Exception.Create('RSA prikey not assigned');
  if (Input = nil) or (Length(Input) = 0) then
  begin
    Result := nil;
    Exit;
  end;
  case AAlg of
    haSHA256: MD := EVP_sha256();
    haSHA384: MD := EVP_sha384();
    haSHA512: MD := EVP_sha512();
  else
    Assert(False);
    MD := nil;
  end;
  Ctx := EVP_MD_CTX_create;
  try
    pKey := EVP_PKEY_new;
    try
      if EVP_PKEY_set1_RSA(pKey, FPrivateKey.GetRSA) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA key error');
      if EVP_DigestSignInit(Ctx, nil, MD, nil, pKey) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA init error');
      if EVP_DigestUpdate(Ctx, @Input[0], Length(Input)) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA digest error');
      if EVP_DigestSignFinal(Ctx, nil, Size) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA signfinal error');
      SetLength(Result, Size);
      if EVP_DigestSignFinal(Ctx, @Result[0], Size) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA signfinal error');
    finally
      EVP_PKEY_free(pKey);
    end;
  finally
    EVP_MD_CTX_destroy(Ctx);
  end;
end;

function TRSAUtil.PublicEncrypt(const Input: TBytes; Padding: TRSAPadding): TBytes;
var
  Len: Integer;
begin
  if not FPublicKey.IsValid then
    raise Exception.Create('RSA pubkey not assigned');
  Len := RSA_size(FPublicKey.GetRSA);
  SetLength(Result, Len);
  Len := RSA_public_encrypt(Length(Input), PByte(Input), PByte(Result), FPublicKey.GetRSA, PaddingMap[Padding]);
  if Len <= 0 then
    RaiseOpenSSLError('RSA encrypt error');
  SetLength(Result, Len);
end;

procedure TRSAUtil.PublicEncrypt(const InputFileName, OutputFileName: TFileName; Padding: TRSAPadding);
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

procedure TRSAUtil.PublicEncrypt(InputStream, OutputStream: TStream; Padding: TRSAPadding);
var
  InputBuffer: TBytes;
  OutputBuffer: TBytes;
  Len: Integer;
begin
  if not FPublicKey.IsValid then
    raise Exception.Create('RSA pubkey not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  Len := RSA_size(FPublicKey.GetRSA);
  SetLength(OutputBuffer, Len);

  Len := RSA_public_encrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPublicKey.GetRSA, PaddingMap[Padding]);

  if Len <= 0 then
    RaiseOpenSSLError('RSA encrypt error');

  OutputStream.Write(OutputBuffer[0], Len);
end;

function TRSAUtil.PublicVerify(const Input, Signature: TBytes; AAlg: TRSAHashAlgorithm): Boolean;
var
  Ctx: PEVP_MD_CTX;
  MD: PEVP_MD;
  pKey: PEVP_PKEY;
  Ret: Integer;
begin
  if not FPublicKey.IsValid then
    raise Exception.Create('RSA pubkey not assigned');
  if (Input = nil) or (Length(Input) = 0) then
  begin
    Result := Length(Signature) = 0;
    Exit;
  end;
  case AAlg of
    haSHA256: MD := EVP_sha256();
    haSHA384: MD := EVP_sha384();
    haSHA512: MD := EVP_sha512();
  else
    Assert(False);
    MD := nil;
  end;
  Ctx := EVP_MD_CTX_create;
  try
    pKey := EVP_PKEY_new;
    try
      if EVP_PKEY_set1_RSA(pKey, FPublicKey.GetRSA) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA key error');
      if EVP_DigestVerifyInit(Ctx, nil, MD, nil, pKey) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA init error');
      if EVP_DigestUpdate(Ctx, @Input[0], Length(Input)) <> SSL_API_SUCCESS then
        RaiseOpenSSLError('RSA verify error');
      Ret := EVP_DigestVerifyFinal(Ctx, @Signature[0], Length(Signature));
      Result := Ret = 1;
    finally
      EVP_PKEY_free(pKey);
    end;
  finally
    EVP_MD_CTX_destroy(Ctx);
  end;
end;

procedure TRSAUtil.SetPrivateKey(const Value: TCustomRSAPrivateKey);
begin
  FPrivateKey := Value;
end;

procedure TRSAUtil.SetPublicKey(const Value: TCustomRSAPublicKey);
begin
  FPublicKey := Value;
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
  Key: PEVP_PKEY;
begin
  if not Assigned(FPublicRSA) then
  begin
    Key := X509_get_pubkey(FX509);
    try
      FPublicRSA := EVP_PKEY_get1_RSA(Key);
      if not Assigned(FPublicRSA) then
        RaiseOpenSSLError('X509 public key error');
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

function TX509Cerificate.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetPublicRSA, 0) <> SSL_API_SUCCESS then
      RaiseOpenSSLError('X509 print error');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

{ TCustomRSAPrivateKey }

constructor TCustomRSAPrivateKey.Create;
begin
  inherited;
end;

destructor TCustomRSAPrivateKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

function TCustomRSAPrivateKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

procedure TCustomRSAPrivateKey.LoadFromFile(const FileName: string; AFormat: TPrivateKeyFormat = kpDefault);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPrivateKey.LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault);
begin
  raise EOpenSSL.Create('Cannot load private key');
end;

function TCustomRSAPrivateKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetRSA, 0) <> SSL_API_SUCCESS then
      RaiseOpenSSLError('RSA print error');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TCustomRSAPrivateKey.SaveToFile(const FileName: string;
  AFormat: TPrivateKeyFormat);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveToStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPrivateKey.SaveToStream(AStream: TStream; AFormat: TPrivateKeyFormat);
var
  PrivateKey: PBIO;
  KeyLength: Integer;
  Buffer: TBytes;
  pKey: PEVP_PKEY;
begin
  PrivateKey := BIO_new(BIO_s_mem);
  try
    case AFormat of
      kpDefault: begin
        pKey := EVP_PKEY_new(); // TODO: check value
        try
          EVP_PKEY_set1_RSA(pKey, GetRSA); // TODO: check value
          PEM_write_bio_PrivateKey(PrivateKey, pKey, nil, nil, 0, nil, nil);
          KeyLength := BIO_pending(PrivateKey);
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kpRSAPrivateKey: begin
        PEM_write_bio_RSAPrivateKey(PrivateKey, GetRSA, nil, nil, 0, nil, nil);
        KeyLength := BIO_pending(PrivateKey);
      end;
      else
        raise EOpenSSL.Create('Invalid format');
    end;

    SetLength(Buffer, KeyLength);
    BIO_read(PrivateKey, @Buffer[0], KeyLength);
  finally
    BIO_free(PrivateKey);
  end;
  AStream.Write(Buffer[0], Length(Buffer));
end;

{ TCustomRSAPublicKey }

constructor TCustomRSAPublicKey.Create;
begin
  inherited;
end;

destructor TCustomRSAPublicKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

function TCustomRSAPublicKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

procedure TCustomRSAPublicKey.LoadFromCertificate(Cerificate: TX509Cerificate);
begin
  FCerificate := Cerificate;
end;

procedure TCustomRSAPublicKey.LoadFromFile(const FileName: string; AFormat: TPublicKeyFormat);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPublicKey.LoadFromStream(AStream: TStream; AFormat: TPublicKeyFormat);
begin
  raise EOpenSSL.Create('Cannot load private key');
end;

function TCustomRSAPublicKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetRSA, 0) <> SSL_API_SUCCESS then
      RaiseOpenSSLError('RSA print error');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TCustomRSAPublicKey.SaveToFile(const FileName: string;
  AFormat: TPublicKeyFormat);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveToStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPublicKey.SaveToStream(AStream: TStream; AFormat: TPublicKeyFormat);
var
  PublicKey: PBIO;
  KeyLength: Integer;
  Buffer: TBytes;
  pKey: PEVP_PKEY;
begin
  PublicKey := BIO_new(BIO_s_mem);
  try
    case AFormat of
      kfDefault: begin
        pKey := EVP_PKEY_new(); // TODO: check value
        try
          EVP_PKEY_set1_RSA(pKey, GetRSA); // TODO: check value
          PEM_write_bio_PUBKEY(PublicKey, pKey);
          KeyLength := BIO_pending(PublicKey);
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kfRSAPublicKey: begin
        PEM_write_bio_RSAPublicKey(PublicKey, GetRSA);
        KeyLength := BIO_pending(PublicKey);
      end;
      else
        raise EOpenSSL.Create('Invalid format');
    end;

    SetLength(Buffer, KeyLength);
    BIO_read(PublicKey, @Buffer[0], KeyLength);
  finally
    BIO_free(PublicKey);
  end;
  AStream.WriteBuffer(Buffer[0], Length(Buffer));
end;

{ TRSAKeyPair }

constructor TRSAKeyPair.Create;
begin
  inherited;
  FPrivateKey := TRSAKeyPairPrivateKey.Create(Self);
  FPublicKey := TRSAKeyPairPublicKey.Create(Self);
end;

destructor TRSAKeyPair.Destroy;
begin
  FreeRSA;
  FPrivateKey.Free;
  FPublicKey.Free;
  inherited;
end;

procedure TRSAKeyPair.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

procedure TRSAKeyPair.GenerateKey;
const
  DefaultKeySize = 2048;
begin
  GenerateKey(DefaultKeySize);
end;

// Thanks for Allen Drennan
// https://stackoverflow.com/questions/55229772/using-openssl-to-generate-keypairs/55239810#55239810
procedure TRSAKeyPair.GenerateKey(KeySize: Integer);
var
  Bignum: PBIGNUM;
begin
  FreeRSA;

  Bignum := BN_new();
  try
    if BN_set_word(Bignum, RSA_F4) = 1 then
    begin
      FRSA := RSA_new;
      try
        if BN_set_word(Bignum, RSA_F4) <> SSL_API_SUCCESS then
          RaiseOpenSSLError('BN_set_word');

        if RSA_generate_key_ex(FRSA, KeySize, Bignum, nil) <> SSL_API_SUCCESS then
          RaiseOpenSSLError('RSA_generate_key_ex');
      except
        FreeRSA;
        raise;
      end;
    end;
  finally
    BN_free(Bignum);
  end;
end;

{ TRSAPrivateKey }

constructor TRSAPrivateKey.Create;
begin
  inherited;
  FRSA := nil;
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
  Result := FRSA;
end;

procedure TRSAPrivateKey.LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault);
var
  KeyBuffer: pBIO;
  cb: ppem_password_cb;
  pKey: PEVP_PKEY;
begin
  cb := nil;
  if Assigned(FOnNeedPassphrase) then
    cb := @ReadKeyCallback;

  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyBuffer = nil then
    RaiseOpenSSLError('RSA load stream error');
  try

    case AFormat of
      kpDefault: begin

        pKey := PEM_read_bio_PrivateKey(KeyBuffer, nil, cb, nil);
        if not Assigned(pKey) then
          RaiseOpenSSLError('RSA read public key error');

        try
          FRSA := EVP_PKEY_get1_RSA(pKey);

          if not Assigned(FRSA) then
            RaiseOpenSSLError('RSA get public key error');
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kpRSAPrivateKey: begin
        FRSA := PEM_read_bio_RSAPrivateKey(KeyBuffer, nil, cb, nil);
        if not Assigned(FRSA) then
          RaiseOpenSSLError('RSA read private key error');
      end;
      else
        raise EOpenSSL.Create('Invalid format');
    end;

  finally
    BIO_free(KeyBuffer);
  end;
end;

{ TRSAKeyPairPrivateKey }

constructor TRSAKeyPairPrivateKey.Create(KeyPair: TRSAKeyPair);
begin
  inherited Create;
  FKeyPair := KeyPair;
end;

procedure TRSAKeyPairPrivateKey.FreeRSA;
begin
end;

function TRSAKeyPairPrivateKey.GetRSA: PRSA;
begin
  Result := FKeyPair.FRSA;
end;

{ TRSAPublicKey }

constructor TRSAPublicKey.Create;
begin
  inherited;
  FRSA := nil;
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

procedure TRSAPublicKey.LoadFromStream(AStream: TStream; AFormat: TPublicKeyFormat);
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
    case AFormat of
      kfDefault: begin
        pKey := PEM_read_bio_PubKey(KeyBuffer, nil, nil, nil);
        if not Assigned(pKey) then
          RaiseOpenSSLError('RSA read public key error');

        try
          FRSA := EVP_PKEY_get1_RSA(pKey);

          if not Assigned(FRSA) then
            RaiseOpenSSLError('RSA load public key error');
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kfRSAPublicKey: begin
        FRSA := PEM_read_bio_RSAPublicKey(KeyBuffer, nil, nil, nil);
        if not Assigned(FRSA) then
          RaiseOpenSSLError('RSA read public key error');
      end;
      else
        raise EOpenSSL.Create('Invalid format');
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;

{ TRSAKeyPairPublicKey }

constructor TRSAKeyPairPublicKey.Create(KeyPair: TRSAKeyPair);
begin
  inherited Create;
  FKeyPair := KeyPair;
end;

procedure TRSAKeyPairPublicKey.FreeRSA;
begin

end;

function TRSAKeyPairPublicKey.GetRSA: PRSA;
begin
  Result := FKeyPair.FRSA;
end;

end.
