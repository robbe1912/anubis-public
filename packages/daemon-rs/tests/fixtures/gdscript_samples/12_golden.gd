extends Node

var tween: Tween

func _ready():
    tween.tween_property(self, "position", Vector2(100, 100), 1.0)
