unit OpenSSL.DSAUtilsTests;

interface

uses
  TestFramework, OpenSSL.Api_11, OpenSSL.DSAUtils, System.SysUtils, System.Classes,
  OpenSSL.Core;

type
  TDSAUtilTest = class(TTestCase)
  strict private
    FDSAUtil: TDSAUtil;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSignVerify;
  end;

implementation

{ TDSAUtilTest }

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

procedure TDSAUtilTest.TestSignVerify;
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

