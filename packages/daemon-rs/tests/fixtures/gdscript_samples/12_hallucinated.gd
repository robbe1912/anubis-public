extends Node

var tween: Tween

func _ready():
    tween.interpolate_property(self, "position", Vector2(0, 0), Vector2(100, 100), 1.0)
