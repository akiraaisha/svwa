flash = function(msg, type) {
    clear_flash();
    if (typeof(type) === 'undefined') type="flash"
    $('#flash_container').append('<div class="'+ type +'">' + msg + '</div>');
};

clear_flash = function() {
    $('#flash_container').empty();
}
