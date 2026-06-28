package main

var sidebar string = `
<div id="mySidebar" class="sidebar">
  <a href="javascript:void(0)" class="closebtn" onclick="closeNav()">×</a>
  <a href="viewall?nonce=%s">View All</a>
  <a href="viewunique?nonce=%s">View Unique</a>
  <a href="settings?nonce=%s">Settings</a>
  <a href="help?nonce=%s">Help</a>
</div>

<div id="main">
  <button class="openbtn" onclick="openNav()">☰</button>
</div>

<script>
function openNav() {
  document.getElementById("mySidebar").style.width = "250px";
  document.getElementById("main").style.marginLeft = "250px";
}

function closeNav() {
  document.getElementById("mySidebar").style.width = "0";
  document.getElementById("main").style.marginLeft= "0";
}
</script>
`
var style string = `
//html table
table {
  border-collapse: collapse;
  width: 100%;
  font-family: Arial, sans-serif;
}

th, td {
  border: 1px solid #333;
  padding: 12px;
  text-align: left;
}

th {
  background-color: #333;
  color: white;
}

tr:nth-child(odd) {
  background-color: #8A7B7B;
}

tr:nth-child(even) {
  background-color: #1a1a1a;
}

tr:nth-child(odd) td {
  color: #333;
}

tr:nth-child(even) td {
  color: white;
}

//scrolling
:root{
  display:flex;
  flex-direction:column;
  align-content:center;
  justify-content:center;
  height:100dvh;
  background:black;
  font-family:sans-serif;
  color:white;
}

canvas{
  margin:0 auto;
  display:block;
  background-color:white;
  overflow-y: auto;
}

.author{
  position:fixed;
  bottom:1em;
  right:1em;
  font-size:clamp(16px,4dvh,32px);
  color:white;
}

.author a {
  color:#afa;
  font-weight:bold;
}

iframe-container {
    // The parent must have a position other than static for
    //   the absolute positioning of the iframe to work correctly
    position: relative;
    width: 600px;
    height: 400px;
    border: 1px solid black;
  }

  .my-iframe1 {
    position: absolute; // Positions the iframe relative to the container
    top: 0px;
    left: 0px;
    width: 400px;
    height: 450px;
    border: none;
  }

  .my-iframe2 {
    position: absolute; // Positions the iframe relative to the container
    top: 0px;
    left: 500px;
    width: 300px;
    height: 400px;
    border: none;
  }

body {
  font-family: "Lato", sans-serif;
}

.sidebar {
  height: 100%;
  width: 0;
  position: fixed;
  z-index: 1;
  top: 0;
  left: 0;
  background-color: #111;
  overflow-x: hidden;
  transition: 0.5s;
  padding-top: 60px;
}

.sidebar a {
  padding: 8px 8px 8px 32px;
  text-decoration: none;
  font-size: 25px;
  color: #818181;
  display: block;
  transition: 0.3s;
}

.sidebar a:hover {
  color: #f1f1f1;
}

.sidebar .closebtn {
  position: absolute;
  top: 0;
  right: 25px;
  font-size: 36px;
  margin-left: 50px;
}

.openbtn {
  font-size: 20px;
  cursor: pointer;
  background-color: #111;
  color: white;
  padding: 10px 15px;
  border: none;
}

.openbtn:hover {
  background-color: #444;
}

#main {
  transition: margin-left .5s;
  padding: 16px;
}

// On smaller screens, where height is less than 450px, change the style of the sidenav (less padding and a smaller font size)
@media screen and (max-height: 450px) {
  .sidebar {padding-top: 15px;}
  .sidebar a {font-size: 18px;}
}
`
