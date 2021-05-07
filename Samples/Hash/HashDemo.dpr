program HashDemo;

uses
  FastMM4,
  Vcl.Forms,

  OpenSSL.Api_11 in '..\..\Source\OpenSSL.Api_11.pas',
  OpenSSL.Core in '..\..\Source\OpenSSL.Core.pas',
  OpenSSL.HashUtils in '..\..\Source\OpenSSL.HashUtils.pas',

  MainFrm in 'MainFrm.pas' {MainForm};

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
