/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use std::collections::VecDeque;

pub struct Bridge<I, O> {
    input: VecDeque<I>,
    output: VecDeque<O>,
}

impl<I, O> Bridge<I, O> {
    pub fn new() -> Bridge<I, O> {
        Self {
            input: VecDeque::new(),
            output: VecDeque::new(),
        }
    }

    pub fn push_input(&mut self, value: I) {
        self.input.push_back(value);
    }

    pub fn push_output(&mut self, value: O) {
        self.output.push_back(value);
    }

    pub fn pop_input(&mut self) -> Option<I> {
        self.input.pop_front()
    }

    pub fn pop_output(&mut self) -> Option<O> {
        self.output.pop_front()
    }

    pub fn len_input(&self) -> usize {
        self.input.len()
    }

    pub fn len_output(&self) -> usize {
        self.output.len()
    }
}
