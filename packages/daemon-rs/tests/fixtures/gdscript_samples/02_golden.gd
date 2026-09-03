extends Node

var node: Node

func _ready():
    node.connect("pressed", self, "_on_pressed")
