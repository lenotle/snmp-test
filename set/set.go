package set

type empty struct{}
type Set[T comparable] map[T]empty

func New[T comparable]() Set[T] {
	return make(Set[T])
}

func (s Set[T]) Add(elems ...T) {
	for _, elem := range elems {
		s[elem] = empty{}
	}
}

func (s Set[T]) Delete(elem T) {
	delete(s, elem)
}

func (s Set[T]) Has(elem T) bool {
	_, ok := s[elem]
	return ok
}

func (s Set[T]) Len() int {
	return len(s)
}
