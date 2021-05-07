unit MainFrm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls;

type
  TMainForm = class(TForm)
    btnHash: TButton;
    edtHash: TEdit;
    memSrc: TMemo;
    pnlBottom: TPanel;
    rbMD4: TRadioButton;
    rbMD5: TRadioButton;
    rbSHA1: TRadioButton;
    rbSHA256: TRadioButton;
    procedure btnHashClick(Sender: TObject);
  private
    function  HashData(const AData: TBytes): string;
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  OpenSSL.Core, OpenSSL.HashUtils;

{ TMainForm }

procedure TMainForm.btnHashClick(Sender: TObject);
var
  D: TBytes;
begin
  D := TEncoding.Default.GetBytes(memSrc.Text);
  edtHash.Text := HashData(D);
end;

function TMainForm.HashData(const AData: TBytes): string;
var
  MD4: TMD4;
  MD5: TMD5;
  SHA1: TSHA1;
  SHA256: TSHA256;
  R: TBytes;
begin
  if rbMD4.Checked then
  begin
    MD4.Init;
    MD4.Update(Pointer(AData), Length(AData));
    MD4.Final(R);
  end;
  if rbMD5.Checked then
  begin
    MD5.Init;
    MD5.Update(Pointer(AData), Length(AData));
    MD5.Final(R);
  end;
  if rbSHA1.Checked then
  begin
    SHA1.Init;
    SHA1.Update(Pointer(AData), Length(AData));
    SHA1.Final(R);
  end;
  if rbSHA256.Checked then
  begin
    SHA256.Init;
    SHA256.Update(Pointer(AData), Length(AData));
    SHA256.Final(R);
  end;
  Result := BytesToHex(R);
end;

end.
