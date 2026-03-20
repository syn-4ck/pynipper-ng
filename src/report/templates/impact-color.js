$('#vulnTable tr td').each(function(){
    var cellValue = $(this).html();
    if(!isNaN(parseFloat(cellValue))) {
        if (cellValue > 9) {
        $(this).css('background-color','purple');
        } else {
            if (cellValue < 4) {
                $(this).css('background-color','white');
            } else {
                if (cellValue >=9) {
                    $(this).css('background-color','red');
                } else {
                    $(this).css('background-color','yellow');
                }
            }
        }
    }
});