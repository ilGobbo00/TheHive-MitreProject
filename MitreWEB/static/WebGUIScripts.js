/**
 * Function to show sub-techniques in mitre table
 * @param {string} id - ID of the table with sub-techniqeues to display
 */
function showDiv(id) {
    if (document.getElementById(id).style.display === "none") {
        document.getElementById(id).style.display = "block";
    } else {
        document.getElementById(id).style.display = "none";
    }
}

/**
 * Function to auto select / deselect all children of a selected rule in matched_rule table
 * @param ref - Reference to the input checkbox button to get its status
 * @param {string} id - Partial ID of all children of an element in matched_rules_table
 */
function childrenAction(ref, id) {
    let elems = document.querySelectorAll('[id^="' + CSS.escape(id) + '."]')
    for(let e of elems){
        if (document.getElementById(e.id).checked === true && document.getElementById(ref.id).checked !== true) {
                document.getElementById(e.id).checked = false;
                document.getElementById(e.id).disabled = false;
            } else {
                document.getElementById(e.id).checked = true;
                document.getElementById(e.id).disabled = true;
            }
    }
}

/**
 * Function to completely reset all input tag in matched_rule_table (also disabled input)
 * @param el - Reference to the input of matched_rule_table
 */
function resInput(el){
    let elems = el.parentNode.querySelectorAll('input[type=checkbox]');
    for(let e of elems){
        e.checked = false;
        e.disabled = false;
    }
}

/**
 * Function to auto select / deselect all children of a selected category in mitre_table
 * @param ref - Reference to the input checkbox button
 */
function checkSubInput(ref) {
    if (ref.id.includes('root')) {
        let tactic = ref.parentNode.parentNode;

        let e = tactic.nextElementSibling;
        while (e) {                                                           // <input> --> <td> --> <tr>
            let elems = e.querySelectorAll('input[type=checkbox]');
            checkElems(ref, elems);
            e = e.nextElementSibling;
        }
    } else {
        let table = ref.parentNode.querySelector('table');               // <input> --> <td> --> <table>
        let elems = table.querySelectorAll('input[type=checkbox]');
        checkElems(ref, elems);
    }
}

/**
 * Function to manage "All" filter for alerts_table and matched_rules_table
 * @param reference - Reference to the input checkbox button
 * @param {string}ref_table - Name of the target table
 */
function all_filter(reference, ref_table){
    let div_menu = reference.parentNode.parentNode;
    let choices = div_menu.querySelectorAll('input[type=checkbox]');

    // Reference to table with alerts
    let rules_table = document.getElementById(ref_table);                            // Get the reference of the table
    let rows = rules_table.querySelectorAll('tbody > tr');

    if (reference.checked == true) {
        checkElems(reference, choices);
        reference.disabled = false;                                             // checkElems disable all inputs in choices
        for(let r of rows){
            r.style.display = '';
        }
    } else {
        for(let c of choices){
            c.disabled = false;
            c.checked = false;
        }

        for(let r of rows){
            r.style.display = 'none';
        }
    }
}

/**
 * Function (for matched_rule_table) that add a filter for the specified tool
 * @param reference - Input of type checkbox used to get its state
 * @param {string}ref_table - Table with elements to hide or show
 */
function add_filter_for(reference, ref_table){
    let rules_table = document.getElementById(ref_table);                                                               // Get the reference of the table
    let rows = rules_table.querySelectorAll('tbody > tr');

    let selected_elems = Object.values(rows).filter(row => isContainedInsensitive(row.className, reference.id));   // Multi-class compatibility
    if(reference.checked == true){
        for(let elem of selected_elems){
            elem.style.display = '';
        }
    }else{
        for(let elem of selected_elems){
            elem.style.display = 'none';
        }
    }
}

/**
 * Function to search and _highlight all corresponding words. Hide all tables which doesn't have any correspondences
 * @param input - The searching button reference
 * @param {string} target - Id of the tag where the search is performed
 */
function searchCategory(input, target) {
    let parent = document.getElementById(target);
    let tables = parent.querySelectorAll('table.global_table'); //parent.querySelectorAll('table');


    // For each tactic table
    for (let tactic_table of tables) {
        var sub_tables = tactic_table.querySelectorAll('table.sub_technique_table');
        var table_rows = tactic_table.querySelectorAll('tbody tr.technique_row');


        // If there isn't any data in search box, display all table as default
        if (input.value == "") {
            tactic_table.style.display = "inline-table";
            sub_tables.forEach(function (st) {
                st.style.display = "none";
            })
            document.querySelectorAll('._highlight').forEach(function (e){
                e.className = e.className.replaceAll("_highlight", "");
            })
            document.querySelectorAll('.unhighlight').forEach(function (e){
                e.className = e.className.replaceAll("unhighlight", "");
            })
            continue;
        }

        // If there is some text in serch bar and the tactic table contains that text
        if (isContainedInsensitive(tactic_table.textContent, input.value)) {
            tactic_table.style.display = "inline-table"
            for (let r of table_rows) {

                // If technique has sub-technique, check if there are some match inside
                let sub_table = r.querySelector('table');
                if (sub_table != null && isContainedInsensitive(sub_table.textContent, input.value)) {
                    sub_table.style.display = "block";
                    for (let sub_cell of sub_table.querySelectorAll('td')) {
                        sub_cell.className = sub_cell.className.replaceAll("_highlight", "");       // remove duplicates
                        sub_cell.className = sub_cell.className.replaceAll("unhighlight", "");      // remove duplicates
                        if (isContainedInsensitive(sub_cell.textContent, input.value))
                            sub_cell.className += "_highlight ";
                        else
                            sub_cell.className += "unhighlight ";
                    }
                } else {
                    if (sub_table != null) {
                        sub_table.style.display = "none";
                        for (let sub_cell of sub_table.querySelectorAll('td')) {
                            sub_cell.className = sub_cell.className.replaceAll("_highlight", "");   // remove duplicates
                            sub_cell.className = sub_cell.className.replaceAll("unhighlight", "");  // remove duplicates
                            sub_cell.className += "unhighlight";
                        }
                    }
                }

                if(sub_table == null)
                    sub_table = "";

                // Decide if highlight or not technique cell
                let row_cell = r.querySelector('td');
                row_cell.className = row_cell.className.replaceAll("_highlight", "");               // remove duplicates
                row_cell.className = row_cell.className.replaceAll("unhighlight", "");              // remove duplicates
                if (isContainedInsensitive(row_cell.textContent.replaceAll(sub_table.textContent, ""), input.value))
                    row_cell.className += "_highlight ";
                else
                    row_cell.className += "unhighlight ";
            }
            continue;
        }
        tactic_table.style.display = "none";
    }
}

/**
 * Funtion to display only rows with searched text
 * @param input Reference to the input tag
 * @param target
 */
function searchAlert(input, target){
    let table = document.getElementById(target)
    let rows = table.querySelectorAll('tbody tr');

    if(input.value === '')
        for(let r of rows)
            r.style.display = 'table-row'
    else{
        for(let r of rows)
            if(isContainedInsensitive(r.innerText, input.value))
                r.style.display = 'table-row'
            else
                r.style.display = 'none'
    }
}

/**
 * Function to _highlight the cells that contain the string in the search box
 * @param input - Reference to input search box to get the characters inserted
 * @param {string} id - Target where search elements
 */
function searchCategoryMatched(input, id){
    var table = document.getElementById(id);

    if(input.value == ""){
        var cells_to_reset = table.querySelectorAll('td._highlight');
        for(let c of cells_to_reset){
            c.className = c.className.replaceAll("_highlight", "");
            c.className = c.className.replaceAll(" ", "");
        }
    }else{
        var cells = table.querySelectorAll('tbody td');
        for(let c of cells){
            c.className = c.className.replaceAll("_highlight", "");
            c.className = c.className.replaceAll(" ", "");
            if(isContainedInsensitive(c.textContent, input.value))
                c.className += " _highlight ";
        }
    }
}

/**
 * Function to download a CSV file with the status of the alert in the DB
 * @param {string} id - ID of the alert_table
 */
function downloadAlert(id){
    var alert_table = document.getElementById(id);
    var rows = alert_table.querySelectorAll('tr');
    var csv_data = [];

    for(let r of rows){
        if (r.style.display === 'none')
            continue;
        let cells = r.querySelectorAll('th, td');
        if (cells.length < 3)
            continue;

        let curr_row = [];
        curr_row.push(`${sanitize(cells[0].innerText)}`);            // TOOL
        curr_row.push(`${sanitize(cells[1].innerText)}`);            // ID
        if(cells.length === 3) {
            curr_row.push(``);                                        // DESCRIPTION == ""
            curr_row.push(`${sanitize(cells[2].innerText)}`);
        }else{
            curr_row.push(`${sanitize(cells[2].innerText)}`);
            curr_row.push(`${sanitize(cells[3].innerText)}`);
        }
        csv_data.push(curr_row.join(','));
    }
    csv_data = csv_data.join('\r\n');
    downloadCSVFile(csv_data, 'Alerts status');
}

/**
 * Function to download a CSV file with all maches between alert and Mitre categories
 * @param {string} id - ID of the matched_rules_table
 */
function downloadRules(id) {
    let table = document.getElementById(id);
    let rows = table.querySelectorAll('tr');

    let csv_data = []
    let tool = "", alert = "", tactic = "", technique = "", sub_technique = "";
    let begin = true;
    for(let r of rows){
        if(r.style.display === 'none')
            continue;
        /**
         * Number of cells - cases:
         * 1 - There is only a sub-technique
         * 2 - There are a technique and both a sub-technique or not (void cell)
         * 3 - There are a tactic, a technique and both a sub-technique or not (void cell)
         * 4 - Impossible due to the structure of the table
         * 5 - There are a tool, a tactic, a technique and both a sub-technique or not (void cell)
         */
        // Sanification on tatic, technique, sub-technique wouldn't be necessary because Mitre categories should be normal text
        let current_row = []
        let cells = r.querySelectorAll('td, th');

        // Block to avoid copy-paste code
        if(!begin && (cells.length === 1 || cells.length === 2 || cells.length === 3)){
            current_row.push(tool);
            current_row.push(alert);
        }
        switch (cells.length){
            case 1:
                current_row.push(tactic);
                current_row.push(technique);
                break;
            case 2:
                current_row.push(tactic);
                technique = sanitize(cells[0].innerText);
                break;
            case 3:
                tactic = sanitize(cells[0].innerText);
                technique = sanitize(cells[1].innerText);
                break;
            case 5:
                begin = false;
                tool = sanitize(cells[0].innerText);
                alert = sanitize(cells[1].innerText);
                tactic = sanitize(cells[2].innerText);
                technique = sanitize(cells[3].innerText);
                sub_technique = sanitize(cells[4].innerText);
                break;
            default:
                continue;
        }
        for(let cell of cells)
            current_row.push(sanitize(cell.innerText))

        csv_data.push(current_row.join(','));
    }
    csv_data = csv_data.join('\n');
    downloadCSVFile(csv_data, "Matched rules");
}

// ----------------------- Utilities for main functions -----------------------
/**
 * Utility to check if a substring is contained in a string without case sensitive
 * @param {string} container - String which contains "contained" string
 * @param {string} contained - String contained in "container"
 * @returns {boolean}
 */
function isContainedInsensitive(container, contained){
    return container.toLowerCase().includes(contained.toLowerCase())
}

/**
 * Utility function to check and disable multiple item
 * @param ref - Reference of the input checkbox button
 * @param elems - List of elements to change based of ref status
 */
function checkElems(ref, elems) {
    for(let e of elems){
        if (ref.checked === true) {
            e.checked = true;
            e.disabled = true;
        } else {
            e.checked = false;
            e.disabled = false;
        }
    }
}

/**
 * Function to download the csv file
 * @param csv_data - CSV data to download
 * @param {string} name - Name of the downloaded file
 */
function downloadCSVFile(csv_data, name) {
    // Create CSV file object and feed our
    // csv_data into it
    let CSVFile = new Blob([csv_data], {type: "text/csv; charset=UTF-8"});

    // Create to temporary link to initiate
    // download process
    var temp_link = document.createElement('a');

    // Download csv file
    temp_link.download = `${name}.csv`;
    temp_link.href = window.URL.createObjectURL(CSVFile);

    // This link should not be displayed
    temp_link.style.display = "none";
    document.body.appendChild(temp_link);

    // Automatically click the link to trigger download
    temp_link.click();
    document.body.removeChild(temp_link);
}

/**
 * Utility function to sanitize text
 * @param {string}string - String to sanitize
 */
function sanitize(string){
    let re = new RegExp("[^\x21-\x7E\xC0-\xFF \"]", 'gm');
    return string.replaceAll(re, "").replaceAll(`,`,`;`);
}