$('#vulnTable tr td').each(function(){
    var cellValue = $(this).html();
    if(!isNaN(parseFloat(cellValue))) {
        if (cellValue >= 7) {
        $(this).css('background-color','red');
        } else {
            if (cellValue < 4) {
            $(this).css('background-color','green');
            } else {
            $(this).css('background-color','yellow');
            }
        }
    }
});