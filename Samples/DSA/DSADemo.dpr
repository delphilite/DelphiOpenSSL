program DSADemo;

uses
  FastMM4,
  Vcl.Forms,

  OpenSSL.Api_11 in '..\..\Source\OpenSSL.Api_11.pas',
  OpenSSL.Core in '..\..\Source\OpenSSL.Core.pas',
  OpenSSL.Libeay32 in '..\..\Source\OpenSSL.Libeay32.pas',
  OpenSSL.DSAUtils in '..\..\Source\OpenSSL.DSAUtils.pas',

  MainFrm in 'MainFrm.pas' {MainForm};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
