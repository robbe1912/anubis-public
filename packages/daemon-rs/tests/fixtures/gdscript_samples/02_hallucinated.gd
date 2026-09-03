extends Node

var node: Node

func _ready():
    node.connect_signal("pressed", self, "_on_pressed")
