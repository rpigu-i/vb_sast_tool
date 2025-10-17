' form_login.frm - more samples
Option Explicit

Private Sub Login_Click()
    Dim u As String, p As String
    u = Me.txtUser
    p = Me.txtPass

    Dim fs
    Set fs = CreateObject("Scripting.FileSystemObject")
    Dim f
    Set f = fs.OpenTextFile("C:\sensitive\users.txt", 1)  ' File system access
    Dim line
    line = f.ReadLine
    f.Close

    ' Dynamic sql using a helper (simulate custom ExecuteSql)
    Dim q As String
    q = "SELECT * FROM Accounts WHERE Owner = '" & u & "'"
    Call ExecuteSql(q)   ' pattern includes "ExecuteSql" concatenation variant
End Sub
