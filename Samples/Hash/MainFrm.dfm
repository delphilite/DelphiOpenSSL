object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'MainForm'
  ClientHeight = 321
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  PixelsPerInch = 96
  TextHeight = 13
  object memSrc: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 618
    Height = 257
    Align = alClient
    Lines.Strings = (
      '1234567890')
    TabOrder = 0
  end
  object pnlBottom: TPanel
    Left = 0
    Top = 290
    Width = 624
    Height = 31
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    object btnHash: TButton
      AlignWithMargins = True
      Left = 546
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'Hash'
      TabOrder = 0
      OnClick = btnHashClick
    end
    object rbMD4: TRadioButton
      AlignWithMargins = True
      Left = 465
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'MD4'
      TabOrder = 1
    end
    object rbMD5: TRadioButton
      AlignWithMargins = True
      Left = 384
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'MD5'
      TabOrder = 2
    end
    object rbSHA1: TRadioButton
      AlignWithMargins = True
      Left = 303
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'SHA1'
      TabOrder = 3
    end
    object rbSHA256: TRadioButton
      AlignWithMargins = True
      Left = 222
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'SHA256'
      TabOrder = 4
    end
    object rbSHA512: TRadioButton
      AlignWithMargins = True
      Left = 141
      Top = 3
      Width = 75
      Height = 25
      Align = alRight
      Caption = 'SHA512'
      Checked = True
      TabOrder = 5
      TabStop = True
    end
  end
  object edtHash: TEdit
    AlignWithMargins = True
    Left = 3
    Top = 266
    Width = 618
    Height = 21
    Align = alBottom
    Color = clInfoBk
    ReadOnly = True
    TabOrder = 2
  end
end
