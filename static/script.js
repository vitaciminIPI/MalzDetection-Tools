function showInput() {
    var pidField = document.getElementById("pid-field");
    var offsetField = document.getElementById("offset-field");
    var keyField = document.getElementById("key-field");
    var dumpCheck = document.getElementById("dump");
    var physicalField = document.getElementById("physical-field");
    var includeCorrupt = document.getElementById("include-corrupt");
    var recurseCheck = document.getElementById("recurse");
    var command = document.getElementById("command").value;

    if (command == "pslist" || command == "pstree" || command == "psscan" || command == "dlllist" || command == "handles" || command == "malfind" || command == "cmdline") {
        pidField.style.display = "block";
    } else {
        pidField.style.display = "none";
    }
    if (command == "pslist" || command == "pstree" || command == "psscan") {
        physicalField.style.display = "block";
    } else {
        physicalField.style.display = "none";
    }
    if (command == "printkey") {
        offsetField.style.display = "block";
        keyField.style.display = "block";
        recurseCheck.style.display = "block";
    } else {
        offsetField.style.display = "none";
        keyField.style.display = "none";
        recurseCheck.style.display = "none";
    }
    if (command == "netscan" || command == "netstat") {
        includeCorrupt.style.display = "block";
    } else {
        includeCorrupt.style.display = "none";
    }
    if (command == "pslist" || command == "psscan" || command == "dlllist" || command == "malfind") {
        dumpCheck.style.display = "block";
    } else {
        dumpCheck.style.display = "none";
    }
}
function openFileExplorer() {
    // Membuat elemen input untuk memilih file
    var input = document.createElement('input');
    input.type = 'file';

    // Menambahkan event listener untuk mendapatkan path file yang dipilih
    input.onchange = function (event) {
        var file = event.target.files[0];

        // Memeriksa apakah file yang dipilih valid
        if (file) {
            // Mengambil nilai 'name' dari file yang dipilih
            var path = file.name;

            // Mengubah value dari input text dengan id 'file' menjadi path file yang dipilih
            document.getElementById('file-path').value = path;
        } else {
            console.log('Tidak ada file yang dipilih.');
        }
    };

    // Membuka file explorer
    input.click();
}
document.getElementById("my-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var pidValue = document.getElementById("pid-fieldvalue").value;
    var offsetValue = document.getElementById("offset-fieldvalue").value;
    var keyValue = document.getElementById("key-fieldvalue").value;
    if (document.getElementById("dumpCheck").checked) {
        document.getElementById("dumpCheck").value = "true"
    } else {
        document.getElementById("dumpCheck").value = "false"
    }
    if (document.getElementById("include-corruptCheck").checked) {
        document.getElementById("include-corruptCheck").value = "true";
    } else {
        document.getElementById("include-corruptCheck").value = "false"
    }
    if (document.getElementById("recurseCheck").checked) {
        document.getElementById("recurseCheck").value = "true";
    } else {
        document.getElementById("recurseCheck").value = "false"
    }
    if (document.getElementById("physical-check").checked) {
        document.getElementById("physical-check").value = "true";
    } else {
        document.getElementById("physical-check").value = "false"
    }
    var command = document.getElementById("command").value;
    var filePath = document.getElementById("file-path").value;
    $.ajax({
        type: "POST", // method request
        url: "/process-form", // url request
        data: $('form').serialize(), // data yang dikirimkan
        success: function (result) { // response sukses
            // $("#message").text("Command: " + result.message);
            // $.each(result, function (key, value) {
            //     console.log(key + ": " + value);
            //     // atau Anda bisa menambahkan kode untuk menampilkan data tersebut di halaman web
            // });
            var html = '';
            $.each(result, function (key, value) {
                html += key + ": " + value + "<br>";
            });
            $('#result').html(html);
        },
        error: function (xhr, status, error) { // response gagal
            console.log(xhr.responseText); // menampilkan pesan error di console log
        }
    });
});

$(document).ready(function () {
    $('#sidebarCollapse').on('click', function () {
        $('#sidebar').toggleClass('active');
        $(this).toggleClass('dim');
    });
});
var button = document.getElementById("sidebarCollapse"); // Ganti "myButton" dengan ID tombol Anda
var sidebar = document.getElementById("sidebar"); // Ganti "mySidebar" dengan ID sidebar Anda

function shiftButton() {
    if (sidebar.classList.contains("active")) {
        button.style.left = "0";
    } else {
        button.style.left = "260px"; // Ganti "200px" dengan jarak yang diinginkan dari sisi kanan
    }
}

sidebar.addEventListener("transitionend", shiftButton);

sidebar.addEventListener("transitionstart", shiftButton);

window.addEventListener("resize", shiftButton);