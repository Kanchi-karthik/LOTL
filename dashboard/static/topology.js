function drawTopology(){

const canvas = document.getElementById("topology")

if(!canvas) return

const ctx = canvas.getContext("2d")

ctx.clearRect(0,0,canvas.width,canvas.height)

ctx.fillStyle="white"

ctx.font="16px Arial"

ctx.fillText("Kubernetes Cluster",200,40)

ctx.fillText("web-app pod",120,150)

ctx.fillText("payment-service",260,150)

ctx.fillText("user-service",400,150)

ctx.beginPath()

ctx.moveTo(260,60)
ctx.lineTo(150,130)

ctx.moveTo(260,60)
ctx.lineTo(300,130)

ctx.moveTo(260,60)
ctx.lineTo(430,130)

ctx.stroke()

}

window.onload = drawTopology
