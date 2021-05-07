unit OpenSSL.HashUtilsTests;

interface

uses
  TestFramework, OpenSSL.Api_11, OpenSSL.HashUtils, System.SysUtils, System.Classes,
  OpenSSL.Core;

type
  THashUtilTest = class(TTestCase)
  strict private
    FHashUtil: THashUtil;
  private
    procedure TestResult(const AIn, AOut: string);
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestMD4;
    procedure TestMD5;
    procedure TestSHA1;
    procedure TestSHA256;
    procedure TestSHA512;
  end;

implementation

const
  defTestData: string = 'https://zh-google-styleguide.readthedocs.io/en/latest/google-cpp-styleguide/contents/';

{ THashUtilTest }

procedure THashUtilTest.SetUp;
begin
  inherited;
  FHashUtil := nil;
end;

procedure THashUtilTest.TearDown;
begin
  inherited;
  FreeAndNil(FHashUtil);
end;

procedure THashUtilTest.TestMD4;
begin
  FHashUtil := TMD4.Create;
  TestResult(defTestData, '6a42d290939305608ac610a57e8fd02c');
end;

procedure THashUtilTest.TestMD5;
begin
  FHashUtil := TMD5.Create;
  TestResult(defTestData, 'ba317f28c5430abc9023aadcee41dc2f');
end;

procedure THashUtilTest.TestResult(const AIn, AOut: string);
var
  InData, OutData: TBytes;
  S: string;
begin
  InData := TEncoding.UTF8.GetBytes(AIn);
  FHashUtil.Init;
  FHashUtil.Update(Pointer(InData), Length(InData));
  FHashUtil.Final(OutData);
  S := BytesToHex(OutData, True);
  CheckEquals(AOut, S);
end;

procedure THashUtilTest.TestSHA1;
begin
  FHashUtil := TSHA1.Create;
  TestResult(defTestData, 'd300a933f34f921e7fbf560b5c89200002e1867d');
end;

procedure THashUtilTest.TestSHA256;
begin
  FHashUtil := TSHA256.Create;
  TestResult(defTestData, '72be0554c0e39ac9a8eca93c084a441c21e4abdaf055195026544c99b97c7e6a');
end;

procedure THashUtilTest.TestSHA512;
begin
  FHashUtil := TSHA512.Create;
  TestResult(defTestData, 'd7091dd17a10263572a561d1cf99f174e365bc8bbb515d10b0b678709dc2712bd843480be20215dee5e7c086c4406c4d4f2bb52d67eadf91013083025c448df4');
end;

initialization
  // Register any test cases with the test runner
  RegisterTest(THashUtilTest.Suite);

end.

