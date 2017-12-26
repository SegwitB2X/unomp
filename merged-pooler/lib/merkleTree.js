/*

Ported from https://github.com/slush0/stratum-mining/blob/master/lib/merkletree.py

 */

var util = require('./util.js');

var MerkleTree = module.exports = function MerkleTree(data){

    function merkleJoin(h1, h2){
        var joined = Buffer.concat([h1, h2]);
        var dhashed = util.sha256d(joined);
        return dhashed;
    }
    // Used to calculate the steps for adding a coinbase later
    function calculateSteps(data){
        var L = data;
        var steps = [];
        var PreL = [null];
        var StartL = 2;
        var Ll = L.length;

        if (Ll > 1){
            while (true){

                if (Ll === 1)
                    break;

                steps.push(L[1]);

                if (Ll % 2)
                    L.push(L[L.length - 1]);

                var Ld = [];
                var r = util.range(StartL, Ll, 2);
                r.forEach(function(i){
                    Ld.push(merkleJoin(L[i], L[i + 1]));
                });
                L = PreL.concat(Ld);
                Ll = L.length;
            }
        }
       return steps;
    }

    // Used to calculate merkle root without adding a coinbase later
    function calculateRoot(_data) {
        var data = _data; // We dont want to work in-place
        // This is a recursive function
        if(data.length > 1) {
            if(data.length % 2 !== 0)
                data.push(data[data.length - 1]);
            // Hash
            var newData = [];
            for(var i = 0;i < data.length;i += 2) newData.push(merkleJoin(data[i], data[i + 1]));
            return calculateRoot(newData);
        }
        else return data[0];
    }

    this.data = data;
    this.steps = calculateSteps(data);
    this.root = calculateRoot(data[0] == null ? data.slice(1) : data);

}
MerkleTree.prototype = {
    withFirst: function(f){
        this.steps.forEach(function(s){
            f = util.sha256d(Buffer.concat([f, s]));
        });
        return f;
    },
 // Used to develop steps to prove a single hash is part of a merkle root
    getHashProof: function(h) {
        var data = this.data;
        if(data.length == 1) return Buffer.concat([util.varIntBuffer(0), util.packInt32LE(0)]);
        var ind = data.indexOf(h);
        if(ind < 0)
            return undefined; // Cant prove; it is not part of this merkle tree
        var branch_len = 0;
        var hash_buffer = new Buffer(0);
        var side_mask;
        for(;data.length > 1;branch_len++) {
            if(data.length % 2 !== 0)
                data.push(data[data.length - 1]);
            if(ind % 2 === 0) {
                // We need right side
                Buffer.concat([hash_buffer, data[ind + 1]]);
                // No need to write side mask because it should already be 0
            }
            else {
                // We need left side
                Buffer.concat([hash_buffer, data[ind - 1]]);
                side_mask = side_mask & (1 << branch_len);
            }
            // Calculate the next level of the merkle root.
            var newData = [];
            for(var i = 0;i < data.length;i += 2) newData.push(merkleJoin(data[i], data[i + 1]));
            data = newData;
            ind = Math.floor(ind / 2);
        }
        branch_len++;
        return Buffer.concat([util.varIntBuffer(branch_len), hash_buffer, util.serializeNumber(side_mask)]);
    }
};
