flash = function(msg, type, safe) {
    clear_flash();
    if (typeof(type) === 'undefined') type="flash";
    if (typeof(safe) === 'undefined') safe=false;
    $('#flash_container').append('<div class="'+ type +'"></div>');
    if (safe) {
        $('div.' + type).innerHTML(msg);
    } else {
        $('div.' + type).text(msg);
    }
};

clear_flash = function() {
    $('#flash_container').empty();
}
