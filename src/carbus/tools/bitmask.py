def GM(mask, i):
	"""Generate a group mask for a set of bits."""
	return mask << i


def BM(i):
	"""Generate a bitmask value for a particular pin."""
	return GM(1, i)