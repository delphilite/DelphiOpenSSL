object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'MainForm'
  ClientHeight = 441
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object splTop: TSplitter
    Left = 0
    Top = 186
    Width = 624
    Height = 3
    Cursor = crVSplit
    Align = alTop
  end
  object memSrc: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 618
    Height = 180
    Align = alTop
    Lines.Strings = (
      '1234567890')
    TabOrder = 0
  end
  object memSign: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 192
    Width = 618
    Height = 215
    Align = alClient
    TabOrder = 1
  end
  object pnlBottom: TPanel
    Left = 0
    Top = 410
    Width = 624
    Height = 31
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 2
    object btnSign: TButton
      AlignWithMargins = True
      Left = 465
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'Sign'
      TabOrder = 0
      OnClick = btnSignClick
    end
    object btnVerify: TButton
      AlignWithMargins = True
      Left = 546
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'Verify'
      TabOrder = 1
      OnClick = btnVerifyClick
    end
  end
end
