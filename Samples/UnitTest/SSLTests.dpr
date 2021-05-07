program SSLTests;

{$IFDEF CONSOLE_TESTRUNNER}
  {$APPTYPE CONSOLE}
{$ENDIF}

uses
  DUnitTestRunner,

  OpenSSL.Api_11 in '..\..\Source\OpenSSL.Api_11.pas',
  OpenSSL.EncUtils in '..\..\Source\OpenSSL.EncUtils.pas',
  OpenSSL.RandUtils in '..\..\Source\OpenSSL.RandUtils.pas',
  OpenSSL.RSAUtils in '..\..\Source\OpenSSL.RSAUtils.pas',
  OpenSSL.SMIMEUtils in '..\..\Source\OpenSSL.SMIMEUtils.pas',

  OpenSSL.Core in '..\..\Source\OpenSSL.Core.pas',
  OpenSSL.CoreTests in 'OpenSSL.CoreTests.pas',

  OpenSSL.HashUtils in '..\..\Source\OpenSSL.HashUtils.pas',
  OpenSSL.HashUtilsTests in 'OpenSSL.HashUtilsTests.pas',

  OpenSSL.DSAUtils in '..\..\Source\OpenSSL.DSAUtils.pas',
  OpenSSL.DSAUtilsTests in 'OpenSSL.DSAUtilsTests.pas';

{$R *.RES}

begin
  DUnitTestRunner.RunRegisteredTests;
end.

