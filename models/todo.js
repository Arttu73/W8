const mongoose = require('mongoose');


const todoSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true},
    items: { type: [String]}
});

const Todo = mongoose.model('Todo', todoSchema);

module.exports = Todo;