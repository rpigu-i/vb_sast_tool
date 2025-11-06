' module1.bas - sample vulnerabilities
Option Explicit

Public Sub Demo()
    Dim password As String
    password = "SuperSecret123!"   ' Hardcoded password

    Dim sql As String
    sql = "SELECT * FROM Users WHERE Username = '" & username & "'"  ' SQL concatenation / injection risk

    Dim url As String
    url = "http://insecure.example.com/api"  ' Insecure HTTP

    Dim x
    x = Eval("2+2")  ' Eval usage

    Shell "cmd.exe /c dir", vbHide  ' Shell execution

Line1:
    y = "Some random string"
    GoTo OutputLine

OutPutLine:
    Debug.WriteLine(y)

End Sub

Public Sub Demo2()
    GoSub CallMeSubRoutine
    Exit Sub

CallMeSubRoutine
    Dim y
    y = Eval("3+2")

End Sub
