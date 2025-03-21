// Dark Mode Toggle
document.getElementById('theme-toggle').addEventListener('click', function() {
    let html = document.documentElement;
    if (html.getAttribute('data-theme') === 'dark') {
        html.setAttribute('data-theme', 'light');
        this.innerHTML = "🌙 Dark Mode";
    } else {
        html.setAttribute('data-theme', 'dark');
        this.innerHTML = "☀️ Light Mode";
    }
});

// Drag & Drop Feature
let dropArea = document.getElementById("drop-area");
let fileNameDisplay = document.getElementById("fileName");

dropArea.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropArea.classList.add("bg-gray-300", "dark:bg-gray-700");
});

dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("bg-gray-300", "dark:bg-gray-700");
});

dropArea.addEventListener("drop", (e) => {
    e.preventDefault();
    dropArea.classList.remove("bg-gray-300", "dark:bg-gray-700");
    let files = e.dataTransfer.files;
    document.getElementById("fileInput").files = files;
    fileNameDisplay.textContent = files[0].name;
});

document.getElementById("fileInput").addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
        fileNameDisplay.textContent = e.target.files[0].name;
    }
});

function encode() {
    let file = document.getElementById("fileInput").files[0];
    let message = document.getElementById("messageInput").value;
    let password = document.getElementById("passwordInput").value;

    if (!file || !message) {
        alert("Please select a file and enter a message!");
        return;
    }

    let formData = new FormData();
    formData.append("file", file);
    formData.append("message", message);
    formData.append("password", password);

    fetch("/encode", { method: "POST", body: formData })
    .then(response => response.blob())
    .then(blob => {
        let url = window.URL.createObjectURL(blob);
        let a = document.createElement("a");
        a.href = url;
        a.download = "encoded_" + file.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        document.getElementById("output").innerHTML = "<p class='text-green-500'>✅ File encoded successfully! Downloading...</p>";
        document.getElementById("messageContainer").classList.add("hidden");

        document.getElementById("messageInput").value = '';
        document.getElementById("passwordInput").value = '';
        fileNameDisplay.textContent = '';
    })
    .catch(error => {
        document.getElementById("output").innerHTML = "<p class='text-red-500'>❌ Error encoding file.</p>";
    });
}

function decode() {
    let file = document.getElementById("fileInput").files[0];
    let password = document.getElementById("passwordInput").value;

    if (!file) {
        alert("Please select a file to decode!");
        return;
    }

    let formData = new FormData();
    formData.append("file", file);
    formData.append("password", password);

    fetch("/decode", { method: "POST", body: formData })
    .then(response => response.json())
    .then(data => {
        document.getElementById("output").innerHTML = "<p class='text-blue-500'>🔓 Decoded Successfully</p>";
        let messageContainer = document.getElementById("messageContainer");
        messageContainer.textContent = data.message;
        messageContainer.classList.remove("hidden");

        document.getElementById("messageInput").value = '';
        document.getElementById("passwordInput").value = '';
        fileNameDisplay.textContent = '';
    })
    .catch(error => {
        document.getElementById("output").innerHTML = "<p class='text-red-500'>❌ Error decoding file.</p>";
        document.getElementById("messageContainer").classList.add("hidden");
    });
}

window.onload = function() {
    const contributors = document.querySelector('.contributors');
    contributors.classList.add('show');
};