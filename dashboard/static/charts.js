async function loadChart(){

const res = await fetch('/api/commands')

const data = await res.json()

const labels = data.map(d=>d.command)

const counts = data.map(d=>d.count)

new Chart(document.getElementById("commandChart"),{

type:'bar',

data:{
labels:labels,
datasets:[{
label:'Command Frequency',
data:counts,
backgroundColor:'red'
}]
}

})

}

window.onload = loadChart
