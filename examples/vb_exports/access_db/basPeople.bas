Attribute VB_Name = "basPeople"
Option Compare Database
Option Explicit

' Ensures the People table exists; creates it if missing
Public Sub CreatePeopleTableIfMissing()
    Dim db As DAO.Database
    Dim tdef As DAO.TableDef
    Set db = CurrentDb()

    On Error Resume Next
    Set tdef = db.TableDefs("People")
    If Err.Number <> 0 Then
        Err.Clear
        On Error GoTo 0
        Dim sql As String
        sql = "CREATE TABLE People (" & _
              "ID AUTOINCREMENT CONSTRAINT PK_People PRIMARY KEY, " & _
              "FirstName TEXT(50) NOT NULL, " & _
              "LastName TEXT(50) NOT NULL, " & _
              "Age LONG)"
        db.Execute sql, dbFailOnError
        db.Execute "CREATE INDEX IX_People_Name ON People (LastName, FirstName);", dbFailOnError
    End If
    On Error GoTo 0
End Sub

' Adds a person to the People table using a parameterized QueryDef
Public Sub AddPerson(firstName As String, lastName As String, age As Variant)
    Dim db As DAO.Database
    Set db = CurrentDb()

    If Len(Trim$(firstName)) = 0 Or Len(Trim$(lastName)) = 0 Then
        Err.Raise vbObjectError + 1000, "AddPerson", "First and last name are required."
    End If

    Dim ageVal As Variant
    If IsNull(age) Or age = "" Then
        ageVal = Null
    ElseIf Not IsNumeric(age) Then
        Err.Raise vbObjectError + 1001, "AddPerson", "Age must be numeric."
    Else
        ageVal = CLng(age)
    End If

    Dim q As DAO.QueryDef
    Set q = db.CreateQueryDef("", _
        "PARAMETERS pFirst TEXT, pLast TEXT, pAge LONG;" & _
        "INSERT INTO People (FirstName, LastName, Age) VALUES (pFirst, pLast, pAge);")
    q!pFirst = firstName
    q!pLast = lastName
    If IsNull(ageVal) Then
        q!pAge = Null
    Else
        q!pAge = ageVal
    End If
    q.Execute dbFailOnError
End Sub

' Returns a simple CRLF-separated list of people (for quick debug/MsgBox)
Public Function GetPeopleList() As String
    Dim rs As DAO.Recordset, db As DAO.Database
    Set db = CurrentDb()
    Set rs = db.OpenRecordset( _
        "SELECT ID, FirstName, LastName, Age FROM People ORDER BY LastName, FirstName;")
    Dim s As String
    Do While Not rs.EOF
        s = s & rs!ID & " - " & rs!LastName & ", " & rs!FirstName & _
            IIf(IsNull(rs!Age), "", " (" & rs!Age & ")") & vbCrLf
        rs.MoveNext
    Loop
    rs.Close
    GetPeopleList = s
End Function

' Seeds the table with a few rows
Public Sub SeedPeople()
    Dim db As DAO.Database
    Set db = CurrentDb()
    db.Execute "INSERT INTO People(FirstName,LastName,Age) VALUES ('Ada','Lovelace',36);", dbFailOnError
    db.Execute "INSERT INTO People(FirstName,LastName,Age) VALUES ('Alan','Turing',41);", dbFailOnError
    db.Execute "INSERT INTO People(FirstName,LastName,Age) VALUES ('Grace','Hopper',85);", dbFailOnError
End Sub
