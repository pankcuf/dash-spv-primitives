pub struct IndexPath<T> {
    pub indexes: Vec<T>,
    pub length: usize,
}

impl<T> IndexPath<T>  {

    pub fn index_path_with_index(index: T) -> IndexPath<T> {
        IndexPath { indexes: vec![index], length: 1 }
    }
    pub fn index_path_with_indexes(indexes: Vec<T>) -> IndexPath<T> {
        IndexPath { indexes, length: indexes.len() }
    }

    pub fn index_at_position(&self, position: T) -> T {
        self.indexes[position]
    }
}
