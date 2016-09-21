var chai = require('chai');
var should = chai.should();

function add(x, y){
  return x + y;
}

describe('add function', function(){
  it ('should return 5 when receive 3 and 2', function(){
    add(2,3).should.equal(5);
  });
});
