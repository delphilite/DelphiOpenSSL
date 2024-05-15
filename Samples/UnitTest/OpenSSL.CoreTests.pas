unit OpenSSL.CoreTests;

interface

uses
  TestFramework, System.SysUtils, OpenSSL.Api_11, OpenSSL.Core;

type
  TSSLCoreTest = class(TTestCase)
  strict private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBase64Encode;
    procedure TestBytesToHex;
  end;

  function LoadBufferFromFile(const AFile: string): TBytes;

implementation

uses
  System.Classes;

function LoadBufferFromFile(const AFile: string): TBytes;
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

{ TSSLCoreTest }

procedure TSSLCoreTest.SetUp;
begin
  inherited;
end;

procedure TSSLCoreTest.TearDown;
begin
  inherited;
end;

procedure TSSLCoreTest.TestBase64Encode;
var
  S, T, U:  TBytes;
begin
  S := TEncoding.Default.GetBytes('0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789');
  T := Base64Encode(S);
  U := Base64Decode(T);
  CheckEquals(Length(S), Length(U));
  CheckEqualsMem(Pointer(S), Pointer(U), Length(S));


  S := TEncoding.Default.GetBytes('1234');
  T := Base64Encode(S);
  CheckEquals(TEncoding.Default.GetString(T), 'MTIzNA==');
  U := Base64Decode(T);
  CheckEquals(Length(S), Length(U));
  CheckEqualsMem(Pointer(S), Pointer(U), Length(S));

  S := TEncoding.Default.GetBytes('123456789');
  T := Base64Encode(S);
  CheckEquals(TEncoding.Default.GetString(T), 'MTIzNDU2Nzg5');
  U := Base64Decode(T);
  CheckEquals(Length(S), Length(U));
  CheckEqualsMem(Pointer(S), Pointer(U), Length(S));

  S := TEncoding.UTF8.GetBytes('÷–Œƒ≤‚ ‘');
  T := Base64Encode(S);
  CheckEquals(TEncoding.Default.GetString(T), '5Lit5paH5rWL6K+V');
  U := Base64Decode(T);
  CheckEquals(Length(S), Length(U));
  CheckEqualsMem(Pointer(S), Pointer(U), Length(S));

  S := TEncoding.ANSI.GetBytes('≤‚ ‘÷–Œƒ≤‚ ‘:≤‚ ‘');
  T := Base64Encode(S);
  CheckEquals(TEncoding.Default.GetString(T), 'suLK1NbQzsSy4srUOrLiytQ=');
  U := Base64Decode(T);
  CheckEquals(Length(S), Length(U));
  CheckEqualsMem(Pointer(S), Pointer(U), Length(S));
end;

procedure TSSLCoreTest.TestBytesToHex;
var
  B, C: TBytes;
  S, T: string;
begin
  S := '1234567890';
  B := TEncoding.ANSI.GetBytes(S);
  T := BytesToHex(B);
  CheckEquals('31323334353637383930', T);
  C := HexToBytes(T);
  CheckEquals(Length(B), Length(C));
  CheckEqualsMem(Pointer(B), Pointer(C), Length(B));

  S := '≤‚ ‘÷–Œƒ≤‚ ‘:≤‚ ‘';
  B := TEncoding.ANSI.GetBytes(S);
  T := BytesToHex(B, False);
  CheckEquals('B2E2CAD4D6D0CEC4B2E2CAD43AB2E2CAD4', T);
  C := HexToBytes(T);
  CheckEquals(Length(B), Length(C));
  CheckEqualsMem(Pointer(B), Pointer(C), Length(B));
end;

initialization
  // Register any test cases with the test runner
  RegisterTest(TSSLCoreTest.Suite);

end.

