#NoTrayIcon

#Region AutoIt3Wrapper directives section
#AutoIt3Wrapper_Icon=IDM.ico
#AutoIt3Wrapper_Compression=4
#AutoIt3Wrapper_UseUpx=Y
#EndRegion AutoIt3Wrapper directives section

#Region Includes
#include <core.au3>
#include <GUIConstantsEx.au3>
#include <Misc.au3>
#EndRegion Includes

_Singleton(@ScriptName)

#Region Options
Opt('MustDeclareVars', 1)
Opt('GUICloseOnESC', 0)
Opt('TrayMenuMode', 1)
#EndRegion Options

; Script Start - Add your code below here
If $CmdLine[0] = 0 Then
	GUI()
Else
	Switch $CmdLine[1]
		Case '/trial'
			TrialSilent()
			clearTemp()
		Case Else
			GUI()
	EndSwitch
EndIf

Func GUI()
	#Region ### BẮT ĐẦU Khu vực UI ###
	Local $GUI = GUICreate('IDM crack (Qu4nh)', 325, 112)
	Local $tabMain = GUICtrlCreateTab(1, 0, 325, 112)
	Local $tabTrialReset = GUICtrlCreateTabItem('Gia hạn dùng thử')
	Local $btReset = GUICtrlCreateButton('Gia hạn dùng thử IDM', 78, 40, 180, 35)
	GUICtrlSetCursor(-1, 0)
	Local $cbAutorun = GUICtrlCreateCheckbox('Tự động', 128, 80, 80, 20)
	Local $tabRegister = GUICtrlCreateTabItem('Đăng ký')
	Local $btReg = GUICtrlCreateButton('Crack IDM', 78, 40, 180, 35)
	GUICtrlSetCursor(-1, 0)
	Local $lbReg = GUICtrlCreateLabel('Nếu không được thì Crack lại hoặc hạn IDM trial', 27, 80, 282, 17)
	Local $tabHelp = GUICtrlCreateTabItem('Trợ giúp')
	GUICtrlSetState(-1, $GUI_SHOW)
	Local $lbHelp = GUICtrlCreateLabel('', 15, 35, 308, 50)
	GUICtrlSetData(-1, StringFormat('Trial reset ---> Gia hạn IDM trial, sửa lỗi blocked, fake series...\r\nRegister -----> Crack IDM'))
	Local $btForum = GUICtrlCreateButton('Báo lỗi', 45, 73, 115, 25)
	GUICtrlSetCursor(-1, 0)
	Local $btUpdate = GUICtrlCreateButton('Kiểm tra cập nhật', 166, 73, 105, 25)
	GUICtrlSetCursor(-1, 0)
	GUICtrlCreateTabItem('')
	GUICtrlSetState($cbAutorun, $isAuto ? 1 : 4)
	GUISetState(@SW_SHOW)
	#EndRegion ### KẾT THÚC Khu vực UI ###

	While 1
		Local $nMsg = GUIGetMsg()
		Switch $nMsg
			Case $GUI_EVENT_CLOSE
				clearTemp()
				GUIDelete($GUI)
				Exit
			Case $btReset
				GUICtrlSetData($btReset, 'Chờ tí đii...')
				Trial()
				GUICtrlSetData($btReset, 'Gia hạn IDM trial')
				MsgBox(262144, 'Gia hạn IDM trial', 'Bạn có 30 ngày dùng thử mới!')
			Case $cbAutorun
				If GUICtrlRead($cbAutorun) = 1 Then
					GUICtrlSetData($btReset, 'Chờ xíuuu...')
					Trial()
					autorun('trial')
					GUICtrlSetData($btReset, 'Gia hạn IDM trial')
					MsgBox(262144, 'Tự động gia hạn', 'IDM sẽ được gia hạn tự động.')
				Else
					autorun('off')
					MsgBox(262144, 'Tự động gia hạn', 'IDM sẽ KHÔNG được gia hạn tự động.')
				EndIf
			Case $btReg
				Local $Name  = InputBox('Đăng ký IDM', 'Nhập tên của bạn: ', 'Gia hạn IDM trial', '', '', '130')
				If @error <> 1 Then
					If StringLen($Name ) = 0 Then $Name  = 'Gia hạn IDM trial'
					GUICtrlSetData($btReg, 'Chờ đê...')
					Register($Name )
					GUICtrlSetState($cbAutorun, 4)
					GUICtrlSetData($btReg, 'Crack IDM ngay bây giờ')
					MsgBox(262144, 'Crack IDM', 'IDM đã được crack!')
				EndIf
			Case $btForum
				ShellExecute($urlForum)
			Case $btUpdate
				GUICtrlSetData($btUpdate, 'Xin chờ...')
				If GotUpdate() Then
					Local $Download = (MsgBox(1, 'Gia hạn IDM trial', 'Cập nhật ngay?') == 1)
					If $Download Then ShellExecute($urlDownload)
				Else
					MsgBox(262144, 'Gia hạn IDM trial', 'Không tìm thấy bản cập nhật!')
				EndIf
				GUICtrlSetData($btUpdate, 'Kiểm tra cập nhật')
		EndSwitch
	WEnd
EndFunc   ;==>GUI
