program mycomp;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,

  ssl_asn in '..\..\Source\ssl_asn.pas',
  ssl_bio in '..\..\Source\ssl_bio.pas',
  ssl_cms in '..\..\Source\ssl_cms.pas',
  ssl_const in '..\..\Source\ssl_const.pas',
  ssl_err in '..\..\Source\ssl_err.pas',
  ssl_evp in '..\..\Source\ssl_evp.pas',
  ssl_lib in '..\..\Source\ssl_lib.pas',
  ssl_objects in '..\..\Source\ssl_objects.pas',
  ssl_types in '..\..\Source\ssl_types.pas',
  ssl_util in '..\..\Source\ssl_util.pas';

var
  _in, _out: PBIO;
  cms: PCMS_ContentInfo;
  flags: TC_INT;
  fname, foutname: AnsiString;
begin
  try
   Writeln('DEMO CMS uncompress');
   if ParamCount = 0 then
    begin
      Writeln('usage myuncomp.exe filename');
      halt(1);
    end;
    fname := ParamStr(1);
    foutname := ChangeFileExt(fname, '.uncomp');
   SSL_InitERR;
   SSL_InitEVP;
   SSL_InitCMS;
   SSL_InitBIO;
   OPENSSL_add_all_algorithms_noconf;
   try
   _in := BIO_new_file(PansiChar(fname), 'r');
   SSL_CheckError;
   flags := CMS_STREAM or CMS_BINARY;

   cms := SMIME_read_CMS(_in, nil);
   SSL_CheckError;

   _out := BIO_new_file(PAnsiChar(foutname), 'w');
   SSL_CheckError;

   CMS_uncompress(cms, nil, _out, 0);
   SSL_CheckError;
   Writeln('Uncompressed data write into ', foutname);
   finally
     if Assigned(_in) then
       BIO_free(_in);
     if Assigned(cms) then
       CMS_ContentInfo_free(cms);
     if Assigned(_out) then
       BIO_free(_out);
   end;
   { TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

