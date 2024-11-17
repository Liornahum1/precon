import requests,argparse

try:
    vulnerbilties =[]

    def search_vulneratilties(host):
        cve_list = []
        
        if host["cpes"] != None:
            print("\n\n")
            for i in host["cpes"]:
                if "cpe:2.3" in i:
                    cves = requests.get(f"https://cvedb.shodan.io/cves?cpe23={i}").json()
                    print("Vulnerabilties available for this cpe:")
                    for cve in cves["cves"]:
                        if args.file == False:
                            print(cve['cve_id'])
                            print(cve['summary'])
                            print(cve['cvss'])
                            print(cve['references'])
                            print("\n")
                        else:
                            print(f"Fetching CVE:{cve['cve_id']}")
                            vulnerbilties.append([cve['cve_id'],cve['cvss'],cve['summary'],cve['references']])
            if host['vulns'] != None:
                for i in host['vulns']:
                    if i not in cve_list:
                        cve_req = requests.get(f"https://cvedb.shodan.io/cve/{i.strip()}").json()
                        if args.file == False:
                            print(f"CVE: {cve_req['cve_id']}\n")
                            print(f"cvss: {cve_req['cvss']}\n")
                            print(f"summary: {cve_req['summary']}\n")
                            print(f"references: {cve_req['references']}\n")
                        else:
                            print(f"Fetching CVE:{cve_req['cve_id']}")
                            vulnerbilties.append([cve_req['cve_id'],cve_req['cvss'],cve_req['summary'],cve_req['references']])

    def write_to_html():
        global vulnerbilties
        with open(f'{args.target}.html','w') as fl:
                pass
        with open(f'{args.target}.html','a') as fl:
            print("Writing fo file...\nThis may take a while\n")
            fl.write(r"""<html>
                        <head>
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <style>
                        * {
                        box-sizing: border-box;
                        }

                        #myInput {
                        background-image: url('/css/searchicon.png');
                        background-position: 10px 10px;
                        background-repeat: no-repeat;
                        width: 100%;
                        font-size: 16px;
                        padding: 12px 20px 12px 40px;
                        border: 1px solid #ddd;
                        margin-bottom: 12px;
                        }

                        #myTable {
                        border-collapse: collapse;
                        width: 100%;
                        border: 1px solid #ddd;
                        font-size: 18px;
                        }

                        #myTable th, #myTable td {
                        text-align: center;
                        padding: 12px;
                        }

                        #myTable tr {
                        border-bottom: 1px solid #ddd;
                        }

                        #myTable tr.header, #myTable tr:hover {
                        background-color: #f1f1f1;
                        }
                        table, th, td {
                        border:1px solid black;
                        }
                        </style>""" + f"""\n
                        <title>
                                            {args.target}
                                            </title>
                        </head>\n
                        <body>""")
            fl.write(f'<h2 style="text-align: center;">{args.target.strip()} - {host["hostnames"]}</h2>\n')
            fl.write(f'<h2 style="text-align: center;">Open ports:{host["ports"]}</h2>')
            fl.write(f'<h2 style="text-align: center;">CPEs:{host["cpes"]}</h2>')
            fl.write("""<input type="text" id="myInput" onkeyup="myFunction()" placeholder="Search for CVE ID or cvss score.." title="Type in a ID or score number">""")
            fl.write("""<table id="CVE">
<tr class="header">
    <th style="width:60%;">CVE ID</th>
    <th style="width:40%;">cvss</th>
    <th style="width:60%;">Summary</th>
    <th style="width:40%;">reference</th>
</tr>""")
            for i in vulnerbilties:
                fl.write(f"""<tr>
    <td>{i[0]}</td>
    <td>{i[1]}</td>
    <td>{i[2]}</td>
    <td>{i[3]}</td>
</tr>""")
            fl.write("""<script>
function myFunction() {
// Declare variables
var input, filter, table, tr, td, i, j, txtValue;
input = document.getElementById("myInput");
filter = input.value.toUpperCase();
table = document.getElementById("CVE");
tr = table.getElementsByTagName("tr");

// Loop through all table rows, skipping the first row (headers)
for (i = 1; i < tr.length; i++) {
    // Get all cells (td) in the current row
    td = tr[i].getElementsByTagName("td");
    let rowMatch = false; // Track if a match is found in the row

    // Loop through all cells in the row
    for (j = 0; j < td.length; j++) {
    if (td[j]) {
        txtValue = td[j].textContent || td[j].innerText;
        if (txtValue.toUpperCase().indexOf(filter) > -1) {
        rowMatch = true; // A match is found in this cell
        break; // No need to check further cells in this row
        }
    }
    }

    // Show the row if a match is found, otherwise hide it
    tr[i].style.display = rowMatch ? "" : "none";
}
}
</script>
                    </body>""")
            print("Finished creating html file!")



    #accept command line arguments of the target and wether to create an html page out of the results
    parser = argparse.ArgumentParser()

    parser.add_argument("-t","--target",help="Enter target IP")
    parser.add_argument("-f","--file",help="Write results to html file",default=False,action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    #query internetdb and cve db for host information and vulnerabilties
    host = requests.get(f"https://internetdb.shodan.io/{args.target.strip()}").json()
    
    #print result from internet db
    print(f"{args.target.strip()}:\nOpen ports:{host['ports']}\nHostname:{host['hostnames']}\nCpes:{host['cpes']}\nvulnerabilties:{host['vulns']}")
    search_vulneratilties(host)
    #search vulnerabilties for cpes associated with the target and print results from cve db
    

    #write result to html file if set to true
    if args.file != False:
        write_to_html()

except requests.exceptions.ConnectionError:
    print("Connection Error\n")
