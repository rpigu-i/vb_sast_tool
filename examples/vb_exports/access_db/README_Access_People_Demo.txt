ACCESS EXAMPLE: Table + VBA Data Manipulation

WHAT THIS GIVES YOU
- A standard VBA module (basPeople.bas) with:
  - CreatePeopleTableIfMissing: creates People table if missing
  - AddPerson: adds a row using DAO + parameterized QueryDef
  - GetPeopleList: quick string view of the table
  - SeedPeople: optional demo data
- A snippet for a form's code-behind (frmPeopleManager_code.txt) that:
  - Adds people via text boxes + Add button
  - Refreshes a ListBox showing the People table

QUICK SETUP (Access desktop, 2016/2019/365)
1) Create/open a blank .accdb.
2) Enable "Trust access to the VBA project object model" (File > Options > Trust Center > Trust Center Settings > Macro Settings).
3) Press ALT+F11 to open the VBA editor.
4) Tools > References... ensure "Microsoft Office XX.0 Access database engine Object Library" is checked (DAO).
5) Import the module:
   - File > Import File... select basPeople.bas
6) Create the table (either method):
   - Immediate Window (Ctrl+G): type `CreatePeopleTableIfMissing` and press Enter
     OR
   - Create > Query Design > SQL View, paste create_people_table.sql and Run.
   - Optional: run `SeedPeople` from the Immediate Window to add demo rows.
7) Build the form:
   - Create > Form Design
   - Add 3 Text Boxes: Name them txtFirstName, txtLastName, txtAge; set their Labels to "First name", "Last name", "Age".
   - Add a List Box: Name it lstPeople.
   - Add 2 Buttons: Name them btnAdd (Caption: Add), btnList (Caption: Refresh).
   - Open the form's property sheet > Event tab:
     - On Load: [Event Procedure] then click "..." and paste the code from frmPeopleManager_code.txt
     - On Click for btnAdd: [Event Procedure] then paste the btnAdd_Click handler
     - On Click for btnList: [Event Procedure] then paste the btnList_Click handler
   - Save as frmPeopleManager.
8) Run it:
   - Open frmPeopleManager. Click Refresh to load any existing rows.
   - Type a first/last/age and click Add. The row appears below.

OPTIONAL
- Make ACCDE: Database Tools > Make ACCDE (use same Access version/bitness as targets).
- Add validation/UI polish (e.g., required fields, input masks).

Enjoy!