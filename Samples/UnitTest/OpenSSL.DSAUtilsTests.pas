unit OpenSSL.DSAUtilsTests;

interface

uses
  TestFramework, OpenSSL.Api_11, OpenSSL.DSAUtils, System.SysUtils, System.Classes,
  OpenSSL.Core;

type
  TDSAUtilTest = class(TTestCase)
  strict private
    FDSAUtil: TDSAUtil;
  private
    function  LoadBufferFromFile(const AFile: string): TBytes;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSignVerifyBuffer;
    procedure TestSignVerifyFile;
  end;

implementation

{ TDSAUtilTest }

function TDSAUtilTest.LoadBufferFromFile(const AFile: string): TBytes;
begin
  with TFileStream.Create(AFile, fmOpenRead or fmShareDenyWrite) do
  try
    SetLength(Result, Size);
    Position := 0;
    ReadBuffer(Pointer(Result)^, Size);
  finally
    Free;
  end;
end;

procedure TDSAUtilTest.SetUp;
begin
  inherited;
  FDSAUtil := TDSAUtil.Create;
end;

procedure TDSAUtilTest.TearDown;
begin
  inherited;
  FreeAndNil(FDSAUtil);
end;

procedure TDSAUtilTest.TestSignVerifyBuffer;
var
  B, D, S: TBytes;
  F: string;
begin
  F := GetModuleName(HInstance);
  D := LoadBufferFromFile(F);

  B := LoadBufferFromFile('..\TestData\dsa_priv.pem');
  FDSAUtil.PrivateKey.LoadFromBuffer(B);
  S := FDSAUtil.PrivateSign(D);

  B := LoadBufferFromFile('..\TestData\dsa_pub.pem');
  FDSAUtil.PublicKey.LoadFromBuffer(B);
  FDSAUtil.PublicVerify(D, S);
end;

procedure TDSAUtilTest.TestSignVerifyFile;
var
  F, S: string;
begin
  F := GetModuleName(HInstance);
  S := F + '.sig';
  FDSAUtil.PrivateKey.LoadFromFile('..\TestData\dsa_priv.pem');
  FDSAUtil.PrivateSign(F, S);

  FDSAUtil.PublicKey.LoadFromFile('..\TestData\dsa_pub.pem');
  FDSAUtil.PublicVerify(F, S);
end;

initialization
  // Register any test cases with the test runner
  RegisterTest(TDSAUtilTest.Suite);

end.

