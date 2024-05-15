unit OpenSSL.RSAUtilsTests;

interface

uses
  TestFramework, OpenSSL.Api_11, OpenSSL.RSAUtils, System.SysUtils, System.Classes,
  OpenSSL.Core;

type
  TRSAUtilTest = class(TTestCase)
  strict private
    FRSAUtil: TRSAUtil;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncryptDecrypt;
    procedure TestSignVerify;
  end;

implementation

uses
  System.IOUtils, OpenSSL.CoreTests;

{ TRSAUtilTest }

procedure TRSAUtilTest.SetUp;
begin
  inherited;
  FRSAUtil := TRSAUtil.Create;
end;

procedure TRSAUtilTest.TearDown;
begin
  inherited;
  FreeAndNil(FRSAUtil);
end;

procedure TRSAUtilTest.TestEncryptDecrypt;
var
  F, B, C: string;
  D, S, T: TBytes;
begin
  B := '中文内容，需要 < 250 字节的内容';
  B := B + B + B + B + B;

  D := TEncoding.UTF8.GetBytes(B); { Length <= 245 }

  F := TPath.GetFullPath('..\TestData\rsa_pub.pem');
  FRSAUtil.PublicKey.LoadFromFile(F);
  S := FRSAUtil.PublicEncrypt(D);

  F := TPath.GetFullPath('..\TestData\rsa_priv.pem');
  FRSAUtil.PrivateKey.LoadFromFile(F);
  T := FRSAUtil.PrivateDecrypt(S);

  C := TEncoding.UTF8.GetString(T);

  CheckEquals(B, C);
end;

procedure TRSAUtilTest.TestSignVerify;
var
  F: string;
  D, S: TBytes;
begin
  F := TPath.GetFullPath('..\TestData\rsa_pub_cert.pem');
  D := LoadBufferFromFile(F);

  F := TPath.GetFullPath('..\TestData\rsa_priv.pem');
  FRSAUtil.PrivateKey.LoadFromFile(F);
  S := FRSAUtil.PrivateSign(D, haSHA512);

  F := TPath.GetFullPath('..\TestData\rsa_pub.pem');
  FRSAUtil.PublicKey.LoadFromFile(F);
  CheckTrue(FRSAUtil.PublicVerify(D, S, haSHA512));
end;

initialization
  // Register any test cases with the test runner
  RegisterTest(TRSAUtilTest.Suite);

end.

