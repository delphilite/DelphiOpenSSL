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
    rbSHA512: TRadioButton;
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
  R: TBytes;
begin
  if rbMD4.Checked then
    R := TMD4.Execute(AData)
  else if rbMD5.Checked then
    R := TMD5.Execute(AData)
  else if rbSHA1.Checked then
    R := TSHA1.Execute(AData)
  else if rbSHA256.Checked then
    R := TSHA256.Execute(AData)
  else if rbSHA512.Checked then
    R := TSHA512.Execute(AData)
  else begin
    R := nil;
    Assert(False);
  end;
  Result := BytesToHex(R);
end;

end.
